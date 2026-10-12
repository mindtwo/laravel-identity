<?php declare(strict_types=1);

namespace Mindtwo\LaravelIdentity\Http\Responses;

use Closure;
use Illuminate\Contracts\Support\Responsable;
use Symfony\Component\HttpFoundation\Response;

/**
 * Renders a view registered on Identity. A string is a Blade view name; a closure
 * receives the view data and may return a view name, a View, a Response, or any
 * Responsable — which is what makes Inertia pages (Inertia::render()) work.
 */
class ViewResponse implements Responsable
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        private readonly Closure|string $view,
        private readonly array $data = [],
    ) {}

    public function toResponse($request): Response
    {
        $view = $this->view instanceof Closure
            ? ($this->view)($this->data)
            : $this->view;

        if ($view instanceof Responsable) {
            return $view->toResponse($request);
        }

        if ($view instanceof Response) {
            return $view;
        }

        if (is_string($view)) {
            return response()->view($view, $this->data);
        }

        return response($view);
    }
}
