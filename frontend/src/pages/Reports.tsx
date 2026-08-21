import {useEffect,useState} from 'react'
import {Download,FileBarChart,FileJson,FileText,Plus,ShieldCheck} from 'lucide-react'
import {api} from '../lib/api'
import type {Project} from '../types'
import {Empty,PageHeader,Spinner} from '../components/ui'

export default function Reports(){
  const [items,setItems]=useState<any[]|null>(null)
  const [projects,setProjects]=useState<Project[]|null>(null)
  const [creating,setCreating]=useState(false)
  const [form,setForm]=useState({project_id:'',report_type:'executive',format:'json'})
  const load=()=>api.get<any[]>('/reports').then(setItems)
  useEffect(()=>{load();api.get<Project[]>('/projects').then(p=>{setProjects(p);if(p[0])setForm(f=>({...f,project_id:p[0].id}))})},[])
  if(!items||!projects)return <Spinner/>
  const create=async()=>{await api.post('/reports',form);setCreating(false);load()}
  const download=(r:any)=>fetch(api.downloadUrl(`/reports/${r.id}/download`),{headers:{Authorization:`Bearer ${localStorage.getItem('netsecure_access')}`}}).then(x=>x.blob()).then(blob=>{const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download=`${r.report_type}.${r.format}`;a.click();URL.revokeObjectURL(u)})
  return <>
    <PageHeader eyebrow="Communicate clearly" title="Reports" description="Executive and technical snapshots with scope, limitations, evidence, and validation warnings." actions={<button className="primary" onClick={()=>setCreating(!creating)}><Plus/>Generate report</button>}/>
    {creating&&<section className="report-builder">
      <div><FileBarChart/><span><b>Build a report snapshot</b><small>Generated content is stored with an audit event.</small></span></div>
      <label>Project<select value={form.project_id} onChange={e=>setForm({...form,project_id:e.target.value})}>{projects.map(p=><option value={p.id} key={p.id}>{p.name}</option>)}</select></label>
      <label>Audience<select value={form.report_type} onChange={e=>setForm({...form,report_type:e.target.value})}><option value="executive">Executive</option><option value="technical">Technical</option></select></label>
      <label>Format<select value={form.format} onChange={e=>setForm({...form,format:e.target.value})}><option value="json">JSON</option><option value="csv">CSV</option><option value="pdf">PDF</option></select></label>
      <button className="primary" onClick={create}>Generate</button>
    </section>}
    <div className="report-types">
      <article><span><FileBarChart/></span><div><b>Executive brief</b><small>Risk, trends, key concerns, and prioritized recommendations.</small></div></article>
      <article><span><FileText/></span><div><b>Technical evidence</b><small>Scope, methodology, inventory, findings, evidence, and limitations.</small></div></article>
      <article><span><ShieldCheck/></span><div><b>Validation statement</b><small>Every report states that automated observations require human validation.</small></div></article>
    </div>
    {items.length===0?<Empty title="No generated reports" body="Create a project snapshot in PDF, JSON, or CSV."/>:<div className="table-panel"><table><thead><tr><th>Report</th><th>Type</th><th>Format</th><th>Generated</th><th>Validation</th><th></th></tr></thead><tbody>{items.map(r=><tr key={r.id}><td><span className="report-name">{r.format==='json'?<FileJson/>:<FileText/>}<b>{r.title}</b></span></td><td>{r.report_type}</td><td><code>{r.format.toUpperCase()}</code></td><td>{new Date(r.created_at).toLocaleString()}</td><td><span className="validation-pill"><ShieldCheck/>Required</span></td><td><button className="icon-button" onClick={()=>download(r)}><Download/></button></td></tr>)}</tbody></table></div>}
  </>
}

