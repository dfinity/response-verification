import initResponseVerification, {
  sayHello,
} from '@dfinity/response-verification';

self.addEventListener('activate', async () => {
  await initResponseVerification();

  console.log(sayHello());
});
