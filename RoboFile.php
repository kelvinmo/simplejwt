<?php

use Robo\Tasks as RoboTasks;
use Robo\Symfony\ConsoleIO;
use Symfony\Component\Finder\Finder;
use PHLAK\SemVer\Version;

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends RoboTasks {
    protected function checkPharReadonly() {
        if (ini_get('phar.readonly')) {
            throw new \Exception('Must set "phar.readonly = Off" in php.ini to build phars.');
        }
    }

    public function phar() {
        $phar_file = 'bin/jwkstool.phar';

        // 1. Check php config
        $this->checkPharReadonly();

        // 2. Set up robo collections and create temp directory
        $main_collection = $this->collectionBuilder();
        $prepare_collection = $this->collectionBuilder();
        $temp = $main_collection->tmpDir();

        // 3. Prepare step
        // (a) Copy files to temp directory
        $prepare_collection->taskMirrorDir([
            'src' => "$temp/src",
            'bin' => "$temp/bin",
            'build' => "$temp/build"
        ]);
        $prepare_collection->taskFilesystemStack()->copy('composer.json', "$temp/composer.json");
        $prepare_collection->taskFilesystemStack()->copy('box.json', "$temp/box.json");

        // (b) composer install
        $prepare_collection->taskComposerInstall()->dir($temp)->noDev();

        // (c) run
        $result = $prepare_collection->run();
        if (!$result->wasSuccessful()) {
            return $result;
        }

        // 4. Run box to create phar
        $box_command = str_replace('/', DIRECTORY_SEPARATOR, 'vendor-bin/build/vendor/bin/box');

        $main_collection->taskExec($box_command)->arg('compile')->arg('-c')->arg("$temp/box.json");
        $main_collection->taskFilesystemStack()->copy("$temp/bin/jwkstool.phar", 'bin/jwkstool.phar', true);

        // 7. Run everything
        return $main_collection->run();
    }

    public function update_copyright() {
        $current_year = date('Y', time());
        $col = $this->collectionBuilder();

        $finder = new Finder();
        $finder->in(['src', 'bin'])->name('*.php')->append(['LICENSE.txt']);

        foreach($finder as $file) {
            $col->taskReplaceInFile($file)
                ->regex('/Copyright \(C\) Kelvin Mo (\d{4})-(\d{4})(\R)/m')
                ->to('Copyright (C) Kelvin Mo $1-'. $current_year . '$3');
            $col->taskReplaceInFile($file)
                ->regex('/Copyright \(C\) Kelvin Mo (\d{4})(\R)/m')
                ->to('Copyright (C) Kelvin Mo $1-'. $current_year . '$2');
        }

        return $col->run();
    }

    /**
     * Prepares a release.
     * 
     * @param string $type one of major, minor, patch, pre-release
     * @param array $opts
     * @option $dry-run Dry-run, do not make changes
     * @option $ignore-worktree Ignore unstaged and uncommitted changes
     * @option $prefix Prefix to be prepended to version number
     * @option $update-changelog Update the Changelog
     * @option $changelog File name to changelog file
     * @option $push Push git changes
     */
    public function release(ConsoleIO $io, $type = 'patch', $opts = [ 'prefix' => 'v', 'dry-run' => false, 'update-changelog' => true, 'changelog' => 'CHANGELOG.md', 'push' => true, 'ignore-worktree' => false ]) {
        // 1. Check parameters and unstage/uncommitted changes
        if (!in_array($type, ['major', 'minor', 'patch', 'pre-release'])) {
            $io->error("type is not one of major, minor, patch, pre-release");
            return 1;
        }

        if (!$opts['ignore-worktree']) {
            $clean_worktree = $this->taskGitStack()
                ->exec('update-index -q --ignore-submodules --refresh')
                ->exec('diff-files --quiet --ignore-submodules')
                ->exec('diff-index --cached --quiet HEAD --ignore-submodules')
                ->run();
            if (!$clean_worktree->wasSuccessful()) {
                $io->error('You have unstaged or uncommitted changes');
                return $clean_worktree;
            }
        }

        // 2. Get the current tag
        $version_task = $this->taskExec('git describe --tags --abbrev=0 HEAD')->run();
        if (!$version_task->wasSuccessful()) {
            return $version_task;
        }

        // 3. Get the current version from tag
        $tag = trim($version_task->getMessage());
        $version = Version::parse($tag);
        $io->say('Current version: ' . (string) $version);

        // 4. Get bumped version
        $new_version = clone $version;
        switch ($type) {
            case 'major': $new_version->incrementMajor(); break;
            case 'minor': $new_version->incrementMinor(); break;
            case 'patch': $new_version->incrementPatch(); break;
            case 'pre-release': $new_version->incrementPrerelease(); break;
        }
        $io->say('New version: ' . (string) $new_version);

        $col = $this->collectionBuilder($io);
        if ($opts['dry-run']) $col->simulated();

        // 5. Update changelog
        if ($opts['update-changelog']) {
            $col->taskReplaceInFile($opts['changelog'])
                ->regex('/^## \[unreleased\]/mi')
                ->to('## [' . (string) $new_version . ']')
                ->limit(1);
            $col->taskReplaceInFile($opts['changelog'])
                ->regex('/^\[unreleased\]:(\s?(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w.-]+)+[\w\-._~:\/?#[\]@!$&\'()*+,;=.]+)\.\.\.HEAD/mi')
                ->to('[' . (string) $new_version . ']:$1...' . $new_version->prefix($opts['prefix']));
        }

        // 6. Add and commit CHANGELOG.md
        $git = $col->taskGitStack();

        if ($opts['update-changelog']) {
            $git->add($opts['changelog']);
            $git->commit('Version ' . (string) $new_version);
        }
        
        // 7. Tag
        $git->tag($new_version->prefix($opts['prefix']));

        // 8. Push
        if ($opts['push']) {
            if ($opts['update-changelog']) $git->push();
            $git->push('--tags');
        }

        return $col->run();
    }
}