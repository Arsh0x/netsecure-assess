const API_URL=import.meta.env.VITE_API_URL||'http://localhost:8000/api'

export class ApiError extends Error{constructor(public status:number,message:string){super(message)}}

async function request<T>(path:string,options:RequestInit={}):Promise<T>{
  const token=localStorage.getItem('netsecure_access')
  const response=await fetch(`${API_URL}${path}`,{...options,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{ }),...options.headers}})
  if(response.status===401&&token&&!path.includes('/auth/')){localStorage.removeItem('netsecure_access');localStorage.removeItem('netsecure_refresh');window.dispatchEvent(new Event('netsecure-session-expired'))}
  if(!response.ok){let message='Request failed';try{const body=await response.json();message=typeof body.detail==='string'?body.detail:JSON.stringify(body.detail)}catch{}throw new ApiError(response.status,message)}
  return response.json() as Promise<T>
}

export const api={
  get:<T>(path:string)=>request<T>(path),
  post:<T>(path:string,body:unknown)=>request<T>(path,{method:'POST',body:JSON.stringify(body)}),
  put:<T>(path:string,body:unknown)=>request<T>(path,{method:'PUT',body:JSON.stringify(body)}),
  patch:<T>(path:string,body:unknown)=>request<T>(path,{method:'PATCH',body:JSON.stringify(body)}),
  downloadUrl:(path:string)=>`${API_URL}${path}`,
}

