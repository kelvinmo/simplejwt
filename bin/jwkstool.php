<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2021
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

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command as SymfonyCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\Table;

use SimpleJWT\Keys\Key;
use SimpleJWT\Keys\KeyFactory;
use SimpleJWT\Keys\KeyException;
use SimpleJWT\Keys\KeySet;

abstract class Command extends SymfonyCommand {

    private $password = null;

    protected function configure() {
        $this->addArgument('jwks_file', InputArgument::REQUIRED, 'The file name of the key store');
        $this->addOption('password', 'p', InputOption::VALUE_REQUIRED, 'The password used to encrypt the key store');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        if ($input->getOption('password')) {
            $this->password = $input->getOption('password');
        }
    }

    protected function loadKeySet($jwks) {
        $set = new KeySet();
        $set->load($jwks, $this->password);
        return $set;
    }

    protected function saveKeySet($set) {
        return $set->toJWKS($this->password);
    }
}

abstract class SelectKeyCommand extends Command {
    protected $set;

    protected function configure() {
        parent::configure();
        $this->addArgument('kid', InputArgument::OPTIONAL, 'Select the key with this ID');
        $this->addOption('use', null, InputOption::VALUE_REQUIRED, 'Select the key with this use');
        $this->addOption('op', null, InputOption::VALUE_REQUIRED, 'Select the key with this operation');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);
    }

    protected function selectKey(InputInterface $input, OutputInterface $output) {
        if ($input->getArgument('kid')) {
            if ($input->getOption('use') || $input->getOption('op')) {
                $output->writeln('Warning: key id specified, ignoring --use and --op');
            }
            $key = $this->set->getById($input->getArgument('kid'), true);

        } else {
            $criteria = [];
            if ($input->getOption('use')) $criteria['use'] = $input->getOption('use');
            if ($input->getOption('op')) $criteria['key_ops'] = explode(',', $input->getOption('op'));
            $key = $this->set->get($criteria);
        }

        if ($key != null) return $key;

        $output->writeln('Key not found');
        return null;
    }
}

class AddCommand extends Command {
    protected function configure() {
        parent::configure();
        $this->setName('add')->setDescription('Adds a key to the key store');
        $this->addArgument('key_file', InputArgument::REQUIRED, 'The file name of the key to add');
        $this->addOption('id', null, InputOption::VALUE_REQUIRED, 'The key id');
        $this->addOption('create', 'c', InputOption::VALUE_NONE, 'Creates a new key store if it does not exist');
        $this->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'The key format: auto, json, pem', 'auto');
        $this->addOption('use', null, InputOption::VALUE_REQUIRED, 'The key use: sig, enc');
        $this->addOption('ops', null, InputOption::VALUE_REQUIRED, 'The key operations, delimited by commas');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);

        $key_file = $input->getArgument('key_file');
        if (!file_exists($key_file)) {
            $output->writeln('File not found: ' . $key_file);
            return 1;
        }

        $jwks_file = $input->getArgument('jwks_file');
        if (file_exists($jwks_file)) {
            $set = $this->loadKeySet(file_get_contents($jwks_file));
        } else {
            if ($input->getOption('create')) {
                $set = new KeySet();
            } else {
                $output->writeln('File not found: ' . $jwks_file);
                return 1;
            }
        }

        try {
            $key = KeyFactory::create(file_get_contents($key_file), $input->getOption('format'));
        } catch (KeyException $e) {
            $output->writeln($e->getMessage());
            return 2;
        }
        if ($key == null) {
            $output->writeln('Key format or type not recognised');
            return 2;
        }

        if ($input->getOption('id')) $key->setKeyId($input->getOption('id'));
        if ($input->getOption('use')) $key->setUse($input->getOption('use'));
        if ($input->getOption('ops')) $key->setOperations($input->getOption('ops'));

        try {
            $set->add($key);
        } catch (KeyException $e) {
            $output->writeln($e->getMessage());
            return 2;
        }
        $output->writeln('Added key: ' . $key->getKeyId());

        file_put_contents($jwks_file, $this->saveKeySet($set));
    }
}

class ListKeysCommand extends Command {
    protected function configure() {
        parent::configure();
        $this->setName('list-keys')->setDescription('Lists the set of keys in the key store');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);

        $jwks_file = $input->getArgument('jwks_file');

        if (!file_exists($jwks_file)) {
            $output->writeln('File not found: ' . $jwks_file);
            return 1;
        }

        $set = $this->loadKeySet(file_get_contents($jwks_file));

        $table = new Table($output);
        $table->setStyle('borderless');
        $table->setHeaders(['ID', 'Type', 'Size', 'Use', 'Ops']);

        foreach ($set->getKeys() as $key) {
            $id = $key->getKeyId();
            if (strlen($id) > 7) $id = substr($id, 0, 7) . '...';

            $kty = $key->getKeyType();
            if (!$key->isPublic()) $kty .= '*';

            $size = $key->getSize();

            $use = $key->getUse();
            if ($use == null) $use = '';

            $ops = $key->getOperations();
            if ($ops == null) $ops = [];
            $ops = implode(',', $ops);

            $table->addRow([$id, $kty, $size, $use, $ops]);
        }

        $table->render();
    }
}

class RemoveCommand extends SelectKeyCommand {
    protected function configure() {
        parent::configure();
        $this->setName('remove')->setDescription('Removes a key from the key store');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        parent::execute($input, $output);

        $jwks_file = $input->getArgument('jwks_file');
        if (!file_exists($jwks_file)) {
            $output->writeln('File not found: ' . $jwks_file);
            return 1;
        }

        $this->set = $this->loadKeySet(file_get_contents($jwks_file));
        $key = $this->selectKey($input, $output);

        if ($key) {
            $this->set->remove($key);

            $output->writeln('Removed key: ' . $key->getKeyId());

            file_put_contents($jwks_file, $this->saveKeySet($this->set));
        }
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

        $jwks_file = $input->getArgument('jwks_file');
        if (!file_exists($jwks_file)) {
            $output->writeln('File not found: ' . $jwks_file);
            return 1;
        }

        $this->set = $this->loadKeySet(file_get_contents($jwks_file));
        $key = $this->selectKey($input, $output);

        if ($key) {
            switch ($input->getOption('format')) {
                case 'json':
                    $export = $key->toJSON();
                    break;
                case 'pem':
                    try {
                        $export = $key->toPEM();
                    } catch (\Exception $e) {
                        $output->writeln($e->getMessage());
                    }
                    break;
                default:
                    $output->writeln('Invalid format: ' . $input->getOption('format'));
            }

            if ($input->getOption('output')) {
                file_put_contents($input->getOption('output'), $export);
            } else {
                $output->write($export);
            }
        }
    }

}


$app = new Application();
$app->setName('SimpleJWT JWKS tool');
$app->add(new AddCommand());
$app->add(new ListKeysCommand());
$app->add(new RemoveCommand());
$app->add(new ExportCommand());
$app->run();

?>
