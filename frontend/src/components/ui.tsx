import type {ReactNode} from 'react'
import {AlertTriangle,ArrowUpRight,ShieldCheck} from 'lucide-react'

export function PageHeader({eyebrow,title,description,actions}:{eyebrow?:string;title:string;description?:string;actions?:ReactNode}){return <header className="page-header"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{description&&<p>{description}</p>}</div>{actions&&<div className="header-actions">{actions}</div>}</header>}
export function MetricCard({label,value,detail,icon,accent='green'}:{label:string;value:string|number;detail:string;icon:ReactNode;accent?:string}){return <article className={`metric-card accent-${accent}`}><div className="metric-top"><span className="metric-icon">{icon}</span><ArrowUpRight size={16}/></div><strong>{value}</strong><span>{label}</span><small>{detail}</small></article>}
export function Severity({value}:{value:string}){return <span className={`severity severity-${value.toLowerCase()}`}>{value}</span>}
export function Status({value}:{value:string}){return <span className={`status status-${value.toLowerCase().replace(' ','_')}`}><i/>{value.replaceAll('_',' ')}</span>}
export function Empty({title,body,action}:{title:string;body:string;action?:ReactNode}){return <div className="empty"><ShieldCheck/><h3>{title}</h3><p>{body}</p>{action}</div>}
export function ErrorNotice({message}:{message:string}){return <div className="error-notice"><AlertTriangle size={18}/><span>{message}</span></div>}
export function Spinner(){return <div className="spinner-wrap"><div className="spinner"/><span>Loading secure workspace…</span></div>}
export function RiskBadge({score}:{score:number}){const level=score>80?'critical':score>60?'high':score>40?'elevated':score>20?'moderate':'low';return <span className={`risk-badge risk-${level}`}>{score} · {level}</span>}

