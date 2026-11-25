from ..errors import fail


def require_current_actor(actor):
    if actor.registration_state == "retired":
        fail(
            "actor_retired",
            "This legacy actor is retired; permanently delete it to release its hostname",
            409,
        )
