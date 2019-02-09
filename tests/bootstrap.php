<?php

set_include_path(implode(PATH_SEPARATOR, [
    dirname(__FILE__) . '/../src/',
    dirname(__FILE__) . '/',
    get_include_path(),
]));

chdir(dirname(__FILE__) . '/');
include '../vendor/autoload.php';

?>
