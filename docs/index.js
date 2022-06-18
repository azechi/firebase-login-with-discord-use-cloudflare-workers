
//const APPROOT = "https://azechi.github.io/discord-oauth2-pkce-in-cloudflare-workers/";
const APPROOT = "https://localdev.azechi.net/"
const AUTH_ENDPOINT = "https://login-with-discord.azechi.workers.dev/login";
const TOKEN_ENDPOINT = "https://login-with-discord.azechi.workers.dev/token";
const FIREBASE_API_KEY = "AIzaSyAqPJJnB-QxLDJSIflbOH39apMSLuKP7DQ";

const STORAGE_KEY = "code_verifier";
const storage = window.sessionStorage;

const loaded = new Promise(result => {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', result, {once: true})
  } else {
    result();
  }
});

const url = new URL(window.location);
if (
  ["code", "state"].every(Array.prototype.includes, [
    ...url.searchParams.keys(),
  ])
) {
  handleRedirectCallback();
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  window.history.replaceState({}, document.title, url.href);
}

async function handleRedirectCallback() {
  console.log(
    "handleRedirectCallback",
    "code:",
    url.searchParams.get("code"),
    "state:",
    url.searchParams.get("state")
  );

  const tokenRequest = fetch(TOKEN_ENDPOINT, {
    method: "POST",
    credentials: "include",
    mode: "cors",
    body: new URLSearchParams({
      code_verifier: storage.getItem(STORAGE_KEY),
      code: url.searchParams.get("code"),
      state: url.searchParams.get("state"),
      redirect_uri: APPROOT,
    }),
  })
    .then((res) => res.json());

  const [
    _, 
    token,
    {initializeApp}, 
    {getAuth, signInWithCustomToken, onAuthStateChanged}
  ] = await Promise.all([
    loaded,
    tokenRequest,
    import('https://www.gstatic.com/firebasejs/9.8.3/firebase-app.js'),
    import('https://www.gstatic.com/firebasejs/9.8.3/firebase-auth.js')
  ]);
 
  // initialize default app
  initializeApp({apiKey: FIREBASE_API_KEY});
  const auth = getAuth();
  const user = await signInWithCustomToken(auth, token);
  console.log("signInWithCustomToken: ", user)

  onAuthStateChanged(auth, user =>{
    if(!user){
      console.log("signed out");
      return;
    } 

    console.log("onAuthStateChanged",user);
  });
}


await loaded;
const button = document.getElementById("button");
button.disabled = false;

button.addEventListener("click", async () => {
  console.log("click");
  // screen lock on

  await loginWithRedirect();
});

async function loginWithRedirect() {
  const code_verifier = btoa(
    String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))
  ).replace(/\/|\+|=/g, (x) => ({ "/": "_", "+": "-", "=": "" }[x]));

  storage.setItem(STORAGE_KEY, code_verifier);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([...code_verifier].map((e) => e.charCodeAt(0)))
  );
  const code_challenge = btoa(
    String.fromCharCode(...new Uint8Array(hash))
  ).replace(/\/|\+|=/g, (x) => ({ "/": "_", "+": "-", "=": "" }[x]));

  const p = new URLSearchParams({
    code_challenge: code_challenge,
    code_challenge_method: "S256",
    redirect_uri: APPROOT,
  });

  self.location.assign(`${AUTH_ENDPOINT}?${p}`);
}
