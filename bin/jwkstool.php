<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2023
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

$autoload_paths = [
    __DIR__.'/../vendor/autoload.php', // local
    __DIR__.'/../../../autoload.php' // dependency
];

foreach ($autoload_paths as $path) {
    if (file_exists($path)) {
        require_once $path;
        break;
    }
}

use Symfony\Component\Console\Application as SymfonyApplication;
use Symfony\Component\Console\Command\Command as SymfonyCommand;
use Symfony\Component\Console\Command\HelpCommand as SymfonyHelpCommand;
use Symfony\Component\Console\Command\ListCommand as SymfonyListCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Question\ConfirmationQuestion;

use SimpleJWT\Keys\KeyInterface;
use SimpleJWT\Keys\KeyFactory;
use SimpleJWT\Keys\KeyException;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\PEMInterface;

abstract class Command extends SymfonyCommand {
    /** @var string */
    protected $jwksFile;

    /** @var KeySet $set */
    protected $set;

    /** @var string|null $password */
    private $password = null;

    protected function configure() {
        $this->addArgument('jwks_file', InputArgument::REQUIRED, 'The file name of the key store');
        $this->addOption('password', 'p', InputOption::VALUE_OPTIONAL, 'The password used to encrypt the key store', false);
    }

    protected function execute(InputInterface $input, OutputInterface $output) {
        /** @var string|false|null $password_option */
        $password_option = $input->getOption('password');

        if ($password_option !== false) {
            // --password is specified, but option may not be specified
            if ($password_option == null) {
                /** @var \Symfony\Component\Console\Helper\QuestionHelper $helper */
                $helper = $this->getHelper('question');

                $question = new Question('Enter the password to the key store: ');
                $question->setHidden(true);
                $question->setHiddenFallback(false);
                $question->setValidator(function ($value): string {
                    if (($value == null) || (trim($value) == '')) throw new \RuntimeException('The password cannot be empty');
                    return $value;
                });

                $this->password = $helper->ask($input, $output, $question);
            } else {
                $this->password = $password_option;
            }
        }

        $this->jwksFile = $input->getArgument('jwks_file');
        return 0;
    }

    /**
     * @return void
     */
    protected function loadKeySet(bool $create = false) {
        if (file_exists($this->jwksFile)) {
            $jwks_contents = file_get_contents($this->jwksFile);
            if ($jwks_contents === false) {
                throw new \RuntimeException('Cannot read key set file: ' . $this->jwksFile);
            }
            $this->set = new KeySet();
            $this->set->load($jwks_contents, $this->password);
        } else {
            if ($create) {
                $this->set = new KeySet();
            } else {
                throw new \RuntimeException('Key set file not found: ' . $this->jwksFile);
            }
        }
    }

    /**
     * @return void
     */
    protected function saveKeySet() {
        $results = file_put_contents($this->jwksFile, $this->set->toJWKS($this->password));
        if ($results === false) {
            throw new \RuntimeException('Cannot write key set file: ' . $this->jwksFile);
        }
    }

    protected function formatKey(KeyInterface $key): string {
        $result = $key->getThumbnail();
        if ($key->getKeyId() != null) {
            $result .= ' (kid: ' . $key->getKeyId() . ')';
        }
        return $result;
    }
}

abstract class SelectKeyCommand extends Command {
    protected function configure() {
        parent::configure();
        $this->addArgument('index', InputArgument::OPTIONAL, 'Select the key with this index or ID value');
        $this->addOption('thumb', 't', InputOption::VALUE_REQUIRED, 'Select the key with this thumbprint');
        $this->addOption('query', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Select the key matching the criterion');

        $this->setHelp('For the --query option, the criterion is specified as PROPERTY=VALUE.');
    }

    /**
     * @return KeyInterface|null
     */
    protected function selectKey(InputInterface $input, OutputInterface $output) {
        $index = $input->getArgument('index');
        $thumb = $input->getOption('thumb');
        /** @var array<string> $query */
        $query = $input->getOption('query');
        $key = null;

        if ($index != null) {
            if ($thumb || $query) {
                $output->writeln('<comment>Warning: key id specified, ignoring --thumb and --query</comment>');
            }
            if (is_numeric($index) && (intval($index) >= 0)) {
                $keys = $this->set->getKeys();
                if ($index < count($keys)) $key = $keys[$index];
            } else {
                $key = $this->set->getById($index, true);
            }
        } elseif ($thumb) {
            if ($query) {
                $output->writeln('<comment>Warning: --thumb specified, ignoring --query</comment>');
            }
            $key = $this->set->getByThumbnail($thumb, true);
        } elseif ($query) {
            $criteria = [];
            foreach ($query as $q) {
                list($property, $value) = explode('=', $q, 2);
                $criteria[$property] = $value;
            }
            $key = $this->set->get($criteria);
        }

        if ($key != null) return $key;

        $output->writeln('<error>Key not found</error>');
        return null;
    }
}

class AddCommand extends Command {
    protected function configure() {
        parent::configure();
        $this->setName('add')->setDescription('Adds a key to the key store');
        $this->addArgument('key_file', InputArgument::REQUIRED, 'The file name of the key to add');
        $this->addOption('create', 'c', InputOption::VALUE_NONE, 'Create a new key store if it does not exist');
        $this->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'The key format: auto, json, pem', 'auto');
        $this->addOption('id', null, InputOption::VALUE_REQUIRED, 'Set the key id');
        $this->addOption('use', null, InputOption::VALUE_REQUIRED, 'Set the key use: sig, enc');
        $this->addOption('ops', null, InputOption::VALUE_REQUIRED, 'Set the key operations, delimited by commas');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);

        try {
            $this->loadKeySet($input->getOption('create'));
        } catch (\RuntimeException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 1;
        }
        

        $key_file = $input->getArgument('key_file');
        if (!file_exists($key_file)) {
            $output->writeln('<error>Key file not found: ' . $key_file . '</error>');
            return 1;
        }
        $key_contents = file_get_contents($key_file);
        if ($key_contents === false) {
            $output->writeln('<error>Cannot read key file: ' . $key_file . '</error>');
            return 1;
        }

        try {
            $key = KeyFactory::create($key_contents, $input->getOption('format'));
        } catch (KeyException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 2;
        }
        if ($key == null) {
            $output->writeln('<error>Key format or type not recognised</error>');
            return 2;
        }

        if ($input->getOption('id')) $key->setKeyId($input->getOption('id'));
        if ($input->getOption('use')) $key->setUse($input->getOption('use'));
        if ($input->getOption('ops')) $key->setOperations(explode(',', $input->getOption('ops')));

        try {
            $this->set->add($key);
        } catch (KeyException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 2;
        }
        
        try {
            $this->saveKeySet();
        } catch (\RuntimeException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 1;
        }
        
        $output->writeln('<info>Added key: ' . $this->formatKey($key) . '</info>');
        
        return 0;
    }
}

class ListKeysCommand extends Command {
    protected function configure() {
        parent::configure();
        $this->setName('list')->setDescription('Lists the set of keys in the key store');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);

        try {
            $this->loadKeySet();
        } catch (\RuntimeException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 1;
        }

        $table = new Table($output);
        $table->setStyle('borderless');
        $table->setHeaders(['Idx', 'ID', 'Thumbprint', 'Type', 'Size', 'Use', 'Ops']);

        $i = 0;
        foreach ($this->set->getKeys() as $key) {
            $id = $key->getKeyId();
            if ($id == null) $id = '';

            $thumb = $key->getThumbnail();

            $kty = $key->getKeyType();
            if (!$key->isPublic()) $kty .= '*';

            $size = $key->getSize();

            $use = $key->getUse();
            if ($use == null) $use = '';

            $ops = $key->getOperations();
            if ($ops == null) $ops = [];
            $ops = implode(',', $ops);

            $table->addRow([$i, $id, $thumb, $kty, $size, $use, $ops]);
            $i++;
        }

        $table->render();

        return 0;
    }
}

class RemoveCommand extends SelectKeyCommand {
    protected function configure() {
        parent::configure();
        $this->setName('remove')->setDescription('Removes a key from the key store');
        $this->addOption('force', 'f', InputOption::VALUE_NONE, 'Do not prompt');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);

        try {
            $this->loadKeySet();
        } catch (\RuntimeException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 1;
        }

        $key = $this->selectKey($input, $output);
        $format = $this->formatKey($key);

        if ($key) {
            if (!$input->getOption('force')) {
                /** @var \Symfony\Component\Console\Helper\QuestionHelper $helper */
                $helper = $this->getHelper('question');
                $output->writeln('<question>About to remove key: ' . $format . '</question>');
                $question = new ConfirmationQuestion('Do you wish to delete this key (y/N)? ', false);
                if (!$helper->ask($input, $output, $question)) {
                    return 0;
                }
            }

            $this->set->remove($key);

            try {
                $this->saveKeySet();
            } catch (\RuntimeException $e) {
                $output->writeln('<error>' . $e->getMessage() . '</error>');
                return 1;
            }
            $output->writeln('<info>Removed key: ' . $format . '</info>');
        }

        return 0;
    }
}

class ExportCommand extends SelectKeyCommand {
    protected function configure() {
        parent::configure();
        $this->setName('export')->setDescription('Exports a key in the key store');
        $this->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Export to this file or stdout if omitted');
        $this->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'Export in this key format: json, pem', 'json');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);

        try {
            $this->loadKeySet();
        } catch (\RuntimeException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 1;
        }

        $key = $this->selectKey($input, $output);

        if ($key) {
            switch ($input->getOption('format')) {
                case 'json':
                    $export = json_encode($key->getKeyData());
                    if ($export === false) {
                        $output->writeln('<error>Error in exporting to JSON</error>');
                        return 2;
                    }
                    break;
                case 'pem':
                    if (!($key instanceof PEMInterface)) {
                        $output->writeln('<error>This kind of key cannot be exported into PEM</error>');
                        return 2;
                    }
                    try {
                        $export = $key->toPEM();
                    } catch (\Exception $e) {
                        $output->writeln('<error>' . $e->getMessage() . '</error>');
                        return 2;
                    }
                    break;
                default:
                    $output->writeln('<error>Invalid format: ' . $input->getOption('format') . '</error>');
                    return 1;
            }

            if ($input->getOption('output')) {
                file_put_contents($input->getOption('output'), $export);
            } else {
                $output->write($export);
            }
        }

        return 0;
    }
}

class ListCommandsCommand extends SymfonyListCommand {
    protected function configure() {
        parent::configure();
        $this->setName('list-commands');
        $this->setHidden(true);
    }
}

class Application extends SymfonyApplication {
    protected function getDefaultCommands(): array {
        return [new SymfonyHelpCommand(), new ListCommandsCommand()];
    }
}


$app = new Application();
$app->setName('SimpleJWT JWKS tool');
$app->setDefaultCommand('list-commands');
$app->add(new AddCommand());
$app->add(new ListKeysCommand());
$app->add(new RemoveCommand());
$app->add(new ExportCommand());
$app->run();

?>
