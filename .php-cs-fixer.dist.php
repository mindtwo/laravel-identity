<?php declare(strict_types=1);

use Chiiya\CodeStyle\Config;
use PhpCsFixer\Finder;

return (new Config)
    ->setFinder(
        Finder::create()
            ->in([
                __DIR__.'/src',
                __DIR__.'/config',
                __DIR__.'/database',
                __DIR__.'/routes',
                __DIR__.'/tests',
            ])
            ->name('*.php'),
    )
    ->setRules([
        '@Chiiya' => true,
        '@Chiiya:risky' => true,
    ])
    ->setRiskyAllowed(true);
