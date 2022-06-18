import { buildJsonFetcher, existsUser, createUser, UserRequestProperties } from './google';

import { createCustomToken, importKey } from './googleAuth';

export default {
  async fetch(
    req: Request,
    env: {google: string},
    _cnx: ExecutionContext
  ): Promise<Response>{

    const props = await req.json() as UserRequestProperties;
    const google = JSON.parse(env.google);

    const aud = "https://identitytoolkit.googleapis.com/"
    const fetch = await buildJsonFetcher(aud, google);

    const exists = await existsUser(fetch, props.localId);
    console.log(exists);
    if(exists) {
      console.log("もうすでにあるuidです");
    } else {
      await fetch(createUser(props));
    }

    const key = await importKey(google.private_key);
    const token = await createCustomToken(key, google.client_email, props.localId);


    return new Response(token);
  }
}
