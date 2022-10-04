import initResponseVerification, {
  parseCertificateHeader,
} from '@dfinity/response-verification';

function createHeaderField(name: string, value: string): string {
  let base64Value = btoa(value);

  return `${name}=:${base64Value}:`;
}

self.addEventListener('activate', async () => {
  await initResponseVerification();

  const header = [
    createHeaderField('certificate', 'Hello Certificate!'),
    createHeaderField('tree', 'Hello Tree!'),
  ].join(',');
  const certificateHeader = parseCertificateHeader(header);

  console.log('CertificateHeader.certificate', certificateHeader.certificate);
  console.log('CertificateHeader.tree', certificateHeader.tree);
});
