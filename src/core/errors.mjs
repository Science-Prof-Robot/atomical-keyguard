export class KeyguardError extends Error {
  constructor({ code, safeMessage, requestId, retryable = false }) {
    assertString('code', code);
    assertString('safeMessage', safeMessage);
    if (requestId !== undefined) {
      assertString('requestId', requestId, ' when provided');
    }
    if (typeof retryable !== 'boolean') {
      throw new TypeError('retryable must be a boolean.');
    }

    super(safeMessage);
    this.name = 'KeyguardError';
    this.code = code;
    this.requestId = requestId;
    this.retryable = retryable;
    this.safeMessage = safeMessage;
  }

  toSafeResponse() {
    const response = {
      code: this.code,
      retryable: this.retryable,
      safeMessage: this.safeMessage,
    };

    if (this.requestId !== undefined) {
      response.requestId = this.requestId;
    }

    return response;
  }
}

function assertString(name, value, suffix = '') {
  if (typeof value !== 'string') {
    throw new TypeError(`${name} must be a string${suffix}.`);
  }
}
