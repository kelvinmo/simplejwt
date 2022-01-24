<?php

use Symfony\Component\Finder\Finder;

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks {
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
            'bin' => "$temp/bin"
        ]);
        $prepare_collection->taskFilesystemStack()->copy('composer.json', "$temp/composer.json");

        // (b) composer install
        $prepare_collection->taskComposerInstall()->dir($temp)->noDev();

        // (c) run
        $result = $prepare_collection->run();
        if (!$result->wasSuccessful()) {
            return $result;
        }

        // 4. Prepare phar task
        $phar_task = $main_collection->taskPackPhar($phar_file)
            ->compress('bzip2')
            ->stub('build/jwkstool_pharstub.php');

        // 5. Add files
        $finder = new Finder();
        $finder->in($temp)->name('*.php');
        foreach($finder as $file) {
            $phar_task->addFile($file->getRelativePathname(), $file->getRealPath());
        }
        
        // 6. chmod
        $main_collection->taskFilesystemStack()->chmod($phar_file, 0755);

        // 7. Run everything
        return $main_collection->run();
    }

    public function update_copyright() {
        $current_year = strftime("%Y");

        $finder = new Finder();
        $finder->in(['src', 'bin'])->name('*.php')->append(['COPYING.txt']);

        foreach($finder as $file) {
            $this->taskReplaceInFile($file)
                ->regex('/Copyright \(C\) Kelvin Mo (\d{4})-(\d{4})(\R)/m')
                ->to('Copyright (C) Kelvin Mo $1-'. $current_year . '$3')
                ->run();
            $this->taskReplaceInFile($file)
                ->regex('/Copyright \(C\) Kelvin Mo (\d{4})(\R)/m')
                ->to('Copyright (C) Kelvin Mo $1-'. $current_year . '$2')
                ->run();
        }
    }
}