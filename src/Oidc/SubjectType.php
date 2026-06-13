<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Oidc;

enum SubjectType: string
{
    case Public = 'public';
    case Pairwise = 'pairwise';
}
