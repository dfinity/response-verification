import initResponseVerification, {
  sayHello,
} from '@dfinity/response-verification';

window.addEventListener('load', async () => {
  await initResponseVerification();

  console.log(sayHello());
});
