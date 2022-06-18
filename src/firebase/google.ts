import { fetchJson, authorizer, RequireAuthorize, JSONRequest } from "../apiRequest";
import { generateJwt, KeyInfo } from './googleAuth';

export { buildJsonFetcher, createUser, existsUser };


function queryUsersRequest(project_id: string, query: any) {
  return new Request(
    `https://identitytoolkit.googleapis.com/v1/projects/${project_id}/accounts:query`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(query),
    }) as RequireAuthorize<JSONRequest<{"recordsCount": string}>>;
}

export interface UserRequestProperties {
  localId: string
}

function createUserRequest(project_id: string, userInfo: UserRequestProperties){

  const req = new Request(
    `https://identitytoolkit.googleapis.com/v1/projects/${project_id}/accounts`,
    {
      method: "POST",
      headers: {
        Accept: 'application/json',
        "Content-Type": "application/json"
      },
      body: JSON.stringify(userInfo),
    }
  );

  return req as RequireAuthorize<JSONRequest<{"localId":string}>>;
}


async function buildJsonFetcher(aud: string, keyInfo: KeyInfo & {"project_id": string}): Promise<FetchLauncher>{
  const jwt = await generateJwt(aud, keyInfo);
  const authorize = authorizer(jwt);
  return (req: AuthorizedJsonFetch) => fetchJson(authorize(req(keyInfo.project_id)));
}

function createUser(props: any) {
  return (project_id:string) => createUserRequest(project_id, props);
}
function queryUsers(query:any) {
  return (project_id: string) => queryUsersRequest(project_id, query);
}

type _authorizedJsonFetch<_T> = (project:string) => RequireAuthorize<JSONRequest<_T>>;
interface AuthorizedJsonFetch {
  <T>(project:string): RequireAuthorize<JSONRequest<T>>;
}

interface FetchLauncher {
  <T>(req: _authorizedJsonFetch<T>) : Promise<T>;
}


async function existsUser(fetch: FetchLauncher, localId: string) {

  const query = {
    returnUserInfo: false,
    expression: [{userId: localId}]
  };

  const req = queryUsers(query);
  const {recordsCount} =  await fetch(req);
  return Number(recordsCount) === 1;
}
