import {useEffect,useRef,useState} from 'react'
import {AlertTriangle,ArrowRight,Check,CheckCircle2,FileText,FlaskConical,Network,Printer,RefreshCw,ShieldAlert,SkipForward,X} from 'lucide-react'
import {demoData} from '../data/demoData'
import {MetricCard,PageHeader,Severity,Status} from '../components/ui'

const stageFor=(progress:number)=>Math.min(demoData.scanStages.length-1,Math.floor(progress/17))

export default function DemoPage(){
  const [progress,setProgress]=useState(0)
  const [running,setRunning]=useState(false)
  const [complete,setComplete]=useState(false)
  const [reportOpen,setReportOpen]=useState(false)
  const timer=useRef<number|null>(null)

  const stopTimer=()=>{if(timer.current!==null){window.clearInterval(timer.current);timer.current=null}}
  useEffect(()=>stopTimer,[])

  const runDemo=()=>{
    stopTimer();setProgress(0);setComplete(false);setRunning(true)
    timer.current=window.setInterval(()=>setProgress(current=>{
      const next=Math.min(100,current+2)
      if(next===100){stopTimer();setRunning(false);setComplete(true)}
      return next
    }),180)
  }
  const skip=()=>{stopTimer();setProgress(100);setRunning(false);setComplete(true)}
  const reset=()=>{stopTimer();setProgress(0);setRunning(false);setComplete(false);setReportOpen(false)}
  const currentStage=demoData.scanStages[stageFor(progress)]
  const m=demoData.metrics

  return <div className="demo-page">
    <div className="demo-mode-banner"><FlaskConical/><div><b>DEMO MODE</b><span>All assets, findings, alerts, and traffic information are simulated.</span></div><span className="demo-no-network"><i/>No network activity</span></div>
    <PageHeader eyebrow="Presentation workspace" title="Network security demonstration" description="A guided, simulated assessment designed for safe classroom and stakeholder presentations." actions={complete?<><button className="secondary" onClick={reset}><RefreshCw/>Reset Demo</button><button className="primary" onClick={()=>setReportOpen(true)}><FileText/>View Demo Report</button></>:undefined}/>

    {!complete&&<section className="demo-scan-hero">
      <div className={running?'demo-orbit running':'demo-orbit'}><Network/><i/><i/><i/></div>
      <div className="demo-scan-copy"><span className="panel-kicker">SIMULATED SAFE SCAN</span><h2>{running?currentStage:'Ready to demonstrate'}</h2><p>{running?'Static sample results are being prepared. No packets are sent and no target is contacted.':'Run a polished 9-second walkthrough using only bundled frontend data.'}</p><code>{demoData.target}</code>
        {running&&<><div className="demo-big-progress"><span style={{width:`${progress}%`}}/><b>{progress}%</b></div><div className="demo-stage-list">{demoData.scanStages.map((stage,index)=><span className={index<stageFor(progress)?'done':index===stageFor(progress)?'active':''} key={stage}>{index<stageFor(progress)?<Check/>:<i/>}{stage}</span>)}</div></>}
        <div className="demo-scan-actions">{!running?<button className="primary demo-run" onClick={runDemo}><FlaskConical/>Run Demo Scan <ArrowRight/></button>:<button className="secondary demo-skip" onClick={skip}><SkipForward/>Skip to results</button>}</div>
      </div>
      <aside><ShieldAlert/><b>Safe by design</b><span>Frontend simulation only</span><span>No real scan or PCAP analysis</span><span>No backend requests</span></aside>
    </section>}

    {complete&&<div className="demo-results">
      <section className="demo-complete-strip"><CheckCircle2/><div><b>Demo scan completed</b><span>5 simulated assets analyzed · 10 educational findings generated</span></div><code>00:09 elapsed</code></section>
      <div className="demo-metrics">
        <MetricCard label="Total assets" value={m.totalAssets} detail={`${m.activeAssets} active`} icon={<Network/>}/>
        <MetricCard label="Total findings" value={m.totalFindings} detail={`${m.criticalFindings} critical · ${m.highFindings} high`} icon={<ShieldAlert/>} accent="orange"/>
        <MetricCard label="Security score" value={`${m.securityScore}%`} detail="Control assessment" icon={<CheckCircle2/>} accent="blue"/>
        <MetricCard label="Overall risk" value={m.overallRisk} detail="Prioritize legacy systems" icon={<AlertTriangle/>} accent="red"/>
      </div>
      <div className="demo-severity-summary"><span><i className="critical"/><b>{m.criticalFindings}</b> Critical</span><span><i className="high"/><b>{m.highFindings}</b> High</span><span><i className="medium"/><b>{m.mediumFindings}</b> Medium</span><span><i className="low"/><b>{m.lowFindings}</b> Low</span></div>

      <section className="panel demo-section"><div className="panel-head"><div><span className="panel-kicker">SIMULATED INVENTORY</span><h2>Discovered assets</h2></div><span className="count-pill">5 assets</span></div><div className="table-scroll"><table><thead><tr><th>IP Address</th><th>Hostname</th><th>Device Type</th><th>Open Ports</th><th>Risk</th></tr></thead><tbody>{demoData.assets.map(asset=><tr key={asset.ip}><td><code>{asset.ip}</code></td><td><b>{asset.hostname}</b></td><td>{asset.deviceType}</td><td><code>{asset.openPorts}</code></td><td><Severity value={asset.risk}/></td></tr>)}</tbody></table></div></section>

      <div className="demo-content-grid">
        <section className="panel demo-findings-panel"><div className="panel-head"><div><span className="panel-kicker">VALIDATION REQUIRED</span><h2>Demo findings</h2></div><span className="count-pill">10</span></div><div className="demo-finding-list">{demoData.findings.map(finding=><article key={finding.title}><Severity value={finding.severity}/><div><h3>{finding.title}</h3><code>{finding.asset}</code><p>{finding.description}</p><small><b>Recommendation:</b> {finding.recommendation}</small></div></article>)}</div></section>
        <div className="demo-side-stack">
          <section className="panel"><div className="panel-head"><div><span className="panel-kicker">PROTOCOL DISTRIBUTION</span><h2>Traffic analysis</h2></div></div><div className="demo-protocols">{demoData.traffic.map(protocol=><div key={protocol.name}><span><b>{protocol.name}</b><strong>{protocol.value}%</strong></span><div><i style={{width:`${protocol.value}%`,background:protocol.color}}/></div></div>)}</div><p className="demo-footnote">Simulated aggregate metadata. No packet payloads are used.</p></section>
          <section className="panel"><div className="panel-head"><div><span className="panel-kicker">DEFENSIVE SIGNALS</span><h2>Demo alerts</h2></div></div><div className="demo-alerts">{demoData.alerts.map(alert=><div key={alert.title}><AlertTriangle/><span><b>{alert.title}</b><small><Severity value={alert.severity}/><Status value={alert.status}/></small></span></div>)}</div></section>
        </div>
      </div>

      <section className="panel demo-assessment"><div className="demo-score"><span>OVERALL SECURITY SCORE</span><b>{demoData.assessment.score}%</b><small>Risk level: {demoData.assessment.riskLevel}</small></div><div className="demo-controls"><div className="panel-head"><div><span className="panel-kicker">CONTROL REVIEW</span><h2>Security-assessment result</h2></div></div>{demoData.assessment.controls.map(control=><div key={control.name}><b>{control.name}</b><span className={`control-state ${control.status.toLowerCase().replaceAll(' ','-')}`}>{control.status}</span></div>)}</div><div className="demo-recommendations"><span className="panel-kicker">TOP RECOMMENDATIONS</span>{demoData.recommendations.map((item,index)=><div key={item}><span>0{index+1}</span><b>{item}</b></div>)}</div></section>
    </div>}

    {reportOpen&&<div className="demo-report-wrap"><button className="modal-backdrop" onClick={()=>setReportOpen(false)} aria-label="Close report"/><article className="demo-report-modal"><header><div><span>NETSECURE ASSESS · SIMULATED REPORT</span><h1>{demoData.projectName}</h1><p>Presentation copy · All information is simulated</p></div><button className="modal-x" onClick={()=>setReportOpen(false)}><X/></button></header><div className="demo-report-score"><span><small>Security score</small><b>68%</b></span><span><small>Overall risk</small><b>High</b></span><span><small>Assets</small><b>5</b></span><span><small>Findings</small><b>10</b></span></div><section><h2>Asset summary</h2><p>Five simulated laboratory systems were reviewed. The legacy server and database server require the highest remediation priority.</p></section><section><h2>Important findings</h2><ul>{demoData.findings.filter(f=>['Critical','High'].includes(f.severity)).map(f=><li key={f.title}><Severity value={f.severity}/><span><b>{f.title}</b> — {f.asset}</span></li>)}</ul></section><section><h2>Alerts</h2><ul>{demoData.alerts.map(a=><li key={a.title}><span><b>{a.title}</b> — {a.status}</span></li>)}</ul></section><section><h2>Recommendations</h2><ol>{demoData.recommendations.map(r=><li key={r}>{r}</li>)}</ol></section><footer><span>Demo Mode · Findings require human validation</span><button className="primary" onClick={()=>window.print()}><Printer/>Print Report</button></footer></article></div>}
  </div>
}

