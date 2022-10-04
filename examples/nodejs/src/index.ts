import { parseCertificateHeader } from '@dfinity/response-verification';

function createHeaderField(name: string, value: string): string {
  let base64Value = Buffer.from(value).toString('base64');

  return `${name}=:${base64Value}:`;
}

const header = [
  createHeaderField('certificate', 'Hello Certificate!'),
  createHeaderField('tree', 'Hello Tree!'),
].join(',');
console.log('Header', header);
const certificateHeader = parseCertificateHeader(header);

console.log('CertificateHeader.certificate', certificateHeader.certificate);
console.log('CertificateHeader.tree', certificateHeader.tree);
