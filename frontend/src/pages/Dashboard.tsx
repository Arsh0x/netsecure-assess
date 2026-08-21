import {useEffect,useState} from 'react'
import {Activity,AlertTriangle,ArrowRight,CheckCircle2,ClipboardCheck,FlaskConical,Network,OctagonAlert,Radar,ShieldAlert} from 'lucide-react'
import {Area,AreaChart,Bar,BarChart,CartesianGrid,Cell,Pie,PieChart,ResponsiveContainer,Tooltip,XAxis,YAxis} from 'recharts'
import {Link} from 'react-router-dom'
import {api} from '../lib/api'
import {MetricCard,PageHeader,Spinner} from '../components/ui'

type Dash={metrics:Record<string,number>;severity:{name:string;value:number}[];risk_trend:{date:string;risk:number}[];protocols:{name:string;packets:number;bytes:number}[];top_assets:{id:string;name:string;ip:string;risk:number;ports:number}[];remediation:{name:string;value:number}[]}
const COLORS=['#ff4d67','#ff8157','#f0b95b','#44bc92','#6c8791']

export default function Dashboard(){
  const [data,setData]=useState<Dash|null>(null)
  useEffect(()=>{api.get<Dash>('/dashboard').then(setData)},[])
  if(!data)return <Spinner/>
  const m=data.metrics
  return <>
    <PageHeader eyebrow="Security command center" title="Good afternoon, Riley." description="Your authorized lab is improving. Two findings need attention this week." actions={<><Link className="demo-start-button" to="/demo"><FlaskConical/>Start Demo</Link><Link className="primary" to="/scans/new"><Radar/>New safe scan</Link></>}/>
    <section className="guardrail-banner"><div><ShieldAlert/><span><b>Guardrails are active</b><small>Private ranges only · 64 hosts max · 256 ports max · Live capture off</small></span></div><Link to="/ethics">Review policy <ArrowRight/></Link></section>
    <div className="metrics-grid">
      <MetricCard label="Monitored assets" value={m.assets} detail={`${m.active_assets} active right now`} icon={<Network/>}/>
      <MetricCard label="Open findings" value={m.open_findings} detail="Across authorized projects" icon={<OctagonAlert/>} accent="orange"/>
      <MetricCard label="High priority" value={m.critical_high} detail="Review within 48 hours" icon={<AlertTriangle/>} accent="red"/>
      <MetricCard label="Security posture" value={`${m.assessment_score}%`} detail="+6 points since review" icon={<ClipboardCheck/>} accent="blue"/>
      <MetricCard label="Active alerts" value={m.alerts} detail="2 awaiting triage" icon={<Activity/>} accent="purple"/>
    </div>
    <div className="dashboard-grid">
      <section className="panel span-2"><div className="panel-head"><div><span className="panel-kicker">30-DAY SIGNAL</span><h2>Risk posture trend</h2></div><div className="trend-positive"><CheckCircle2/>Down 18 points</div></div><ResponsiveContainer width="100%" height={255}><AreaChart data={data.risk_trend}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#2bc48a" stopOpacity={.3}/><stop offset="100%" stopColor="#2bc48a" stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5ebe8"/><XAxis dataKey="date" axisLine={false} tickLine={false}/><YAxis domain={[0,100]} axisLine={false} tickLine={false}/><Tooltip/><Area type="monotone" dataKey="risk" stroke="#1aa876" strokeWidth={3} fill="url(#riskFill)"/></AreaChart></ResponsiveContainer></section>
      <section className="panel"><div className="panel-head"><div><span className="panel-kicker">OPEN FINDINGS</span><h2>Severity mix</h2></div></div><div className="donut-wrap"><ResponsiveContainer width="100%" height={210}><PieChart><Pie data={data.severity} innerRadius={62} outerRadius={86} dataKey="value" paddingAngle={3}>{data.severity.map((_,i)=><Cell key={i} fill={COLORS[i]}/>)}</Pie><Tooltip/></PieChart></ResponsiveContainer><div className="donut-center"><b>{m.open_findings}</b><span>total</span></div></div><div className="chart-legend">{data.severity.map((s,i)=><span key={s.name}><i style={{background:COLORS[i]}}/>{s.name}<b>{s.value}</b></span>)}</div></section>
      <section className="panel span-2"><div className="panel-head"><div><span className="panel-kicker">NETWORK METADATA</span><h2>Protocol distribution</h2></div><Link to="/traffic">Explore traffic <ArrowRight/></Link></div><ResponsiveContainer width="100%" height={245}><BarChart data={data.protocols}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5ebe8"/><XAxis dataKey="name" axisLine={false} tickLine={false}/><YAxis axisLine={false} tickLine={false}/><Tooltip/><Bar dataKey="packets" fill="#183e35" radius={[5,5,0,0]}/></BarChart></ResponsiveContainer></section>
      <section className="panel"><div className="panel-head"><div><span className="panel-kicker">PRIORITY QUEUE</span><h2>Top vulnerable assets</h2></div></div><div className="asset-rank">{data.top_assets.map((a,i)=><Link to={`/assets/${a.id}`} key={a.id}><span className="rank">0{i+1}</span><div><b>{a.name}</b><small>{a.ip} · {a.ports} open ports</small></div><strong className={a.risk>60?'danger':''}>{a.risk}</strong></Link>)}</div></section>
    </div>
  </>
}

