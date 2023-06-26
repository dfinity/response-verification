document.querySelector('form').addEventListener('submit', async e => {
  e.preventDefault();

  const name = document.getElementById('name').value.toString();

  document.getElementById('greeting').innerText = `Hello ${name}!`;

  return false;
});
