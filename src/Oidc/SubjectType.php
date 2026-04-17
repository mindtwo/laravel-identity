<?php declare(strict_types=1);

namespace Chiiya\LaravelIdentity\Oidc;

enum SubjectType: string
{
    case Public = 'public';
    case Pairwise = 'pairwise';
}
