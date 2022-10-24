import { verifyRequestResponsePair } from '@dfinity/response-verification';

function createHeaderField(name: string, value: string): string {
  let base64Value = Buffer.from(value).toString('base64');

  return `${name}=:${base64Value}:`;
}

const header = [
  createHeaderField('certificate', 'Hello Certificate!'),
  createHeaderField('tree', 'Hello Tree!'),
].join(',');

const result = verifyRequestResponsePair(
  { headers: [['Ic-Certificate', header]] },
  { headers: [['Ic-Certificate', header]] },
);

console.log('Result', result);
