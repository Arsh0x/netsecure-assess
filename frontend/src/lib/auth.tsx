import {createContext,useContext,useEffect,useMemo,useState,type ReactNode} from 'react'
import {api} from './api'
import type {User} from '../types'

interface AuthValue{user:User|null;loading:boolean;login:(email:string,password:string)=>Promise<void>;logout:()=>void;refresh:()=>Promise<void>}
const AuthContext=createContext<AuthValue|null>(null)
export function AuthProvider({children}:{children:ReactNode}){
  const [user,setUser]=useState<User|null>(null);const [loading,setLoading]=useState(true)
  const refresh=async()=>{try{setUser(await api.get<User>('/auth/me'))}catch{setUser(null)}finally{setLoading(false)}}
  useEffect(()=>{if(localStorage.getItem('netsecure_access'))void refresh();else setLoading(false);const expired=()=>setUser(null);window.addEventListener('netsecure-session-expired',expired);return()=>window.removeEventListener('netsecure-session-expired',expired)},[])
  const login=async(email:string,password:string)=>{const tokens=await api.post<{access_token:string;refresh_token:string}>('/auth/login',{email,password});localStorage.setItem('netsecure_access',tokens.access_token);localStorage.setItem('netsecure_refresh',tokens.refresh_token);await refresh()}
  const logout=()=>{localStorage.removeItem('netsecure_access');localStorage.removeItem('netsecure_refresh');setUser(null)}
  const value=useMemo(()=>({user,loading,login,logout,refresh}),[user,loading])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
export function useAuth(){const value=useContext(AuthContext);if(!value)throw new Error('AuthProvider missing');return value}

