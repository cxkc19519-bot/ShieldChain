"""HTTP Exception handlers for SAGA domain errors."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from saga.domain.errors import (
    ActBindingFailed,
    ActEstablishmentFailed,
    ActExpired,
    ActFutureIssued,
    ActPersistenceError,
    ActQuotaExhausted,
    ConcurrentContactConflict,
    InvalidActInput,
    InvalidRegistrationInput,
    RegistrationPersistenceError,
    SotkAlreadyConsumed,
)

def register_exception_handlers(app: FastAPI) -> None:
    # Instead of SagaError, we map specific known exceptions
    @app.exception_handler(Exception)
    async def saga_error_handler(request: Request, exc: Exception) -> JSONResponse:
        # By default, domain errors that are validation or logic errors return 400
        # Access control / expiry errors return 403
        # Not found / Conflicts return 409 or 404
        # Persistence errors return 500
        
        status_code = 400
        
        if isinstance(exc, (InvalidRegistrationInput, InvalidActInput)):
            status_code = 400
        elif isinstance(exc, (
            ActBindingFailed,
            ActEstablishmentFailed,
            ActExpired,
            ActFutureIssued,
            ActQuotaExhausted,
            SotkAlreadyConsumed,
        )):
            status_code = 403
        elif isinstance(exc, ConcurrentContactConflict):
            status_code = 409
        elif isinstance(exc, (RegistrationPersistenceError, ActPersistenceError)):
            status_code = 500
            
        # IMPORTANT: We do not leak the internal exception string to the client 
        # unless it is a safe validation error. For cryptographic or persistence
        # errors, we return generic messages.
        
        detail = "SAGA Domain Error"
        if status_code == 400:
            detail = str(exc)
        elif status_code == 403:
            detail = "Access denied or protocol validation failed."
        elif status_code == 409:
            detail = "Conflict during concurrent operation."
        elif status_code == 500:
            detail = "Internal persistence error."
            
        return JSONResponse(
            status_code=status_code,
            content={"detail": detail},
        )
