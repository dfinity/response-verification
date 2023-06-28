export class CertificateVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateVerificationError';
  }
}

export class CertificateTimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateTimeError';
  }
}
