#!/usr/bin/env php
<?php
Phar::mapPhar('jwkstool.phar');
require 'phar://jwkstool.phar/bin/jwkstool.php';
__HALT_COMPILER();
