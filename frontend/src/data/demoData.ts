export type DemoSeverity = 'Critical' | 'High' | 'Medium' | 'Low'

export interface DemoAsset {
  ip: string
  hostname: string
  deviceType: string
  openPorts: string
  risk: DemoSeverity
}

export interface DemoFinding {
  title: string
  severity: DemoSeverity
  asset: string
  description: string
  recommendation: string
}

export const demoData = {
  projectName: 'Network Security Laboratory — Demo Assessment',
  target: '192.168.56.0/24 (simulated)',
  scanStages: [
    'Validating authorized target',
    'Discovering devices',
    'Scanning ports',
    'Identifying services',
    'Analyzing vulnerabilities',
    'Generating security report',
    'Scan completed',
  ],
  metrics: {
    totalAssets: 5,
    activeAssets: 5,
    totalFindings: 10,
    criticalFindings: 1,
    highFindings: 3,
    mediumFindings: 4,
    lowFindings: 2,
    securityScore: 68,
    overallRisk: 'High',
  },
  assets: [
    {ip:'192.168.56.10',hostname:'web-server.lab',deviceType:'Web Server',openPorts:'22, 80, 443',risk:'Medium'},
    {ip:'192.168.56.20',hostname:'database-server.lab',deviceType:'Database Server',openPorts:'22, 23, 3306',risk:'High'},
    {ip:'192.168.56.30',hostname:'student-pc.lab',deviceType:'Workstation',openPorts:'135, 445',risk:'Medium'},
    {ip:'192.168.56.40',hostname:'dns-server.lab',deviceType:'DNS Server',openPorts:'22, 53',risk:'Low'},
    {ip:'192.168.56.50',hostname:'legacy-server.lab',deviceType:'Legacy Server',openPorts:'21, 80, 8080',risk:'Critical'},
  ] as DemoAsset[],
  findings: [
    {title:'Insecure Telnet Service',severity:'High',asset:'192.168.56.20',description:'An unencrypted Telnet service is available on port 23.',recommendation:'Disable Telnet and use SSH.'},
    {title:'Unencrypted FTP Service',severity:'High',asset:'192.168.56.50',description:'FTP transmits credentials and data without transport encryption.',recommendation:'Replace FTP with SFTP and restrict access to approved hosts.'},
    {title:'Outdated Web Server',severity:'Critical',asset:'192.168.56.50',description:'The simulated web-server version is outside its supported update lifecycle.',recommendation:'Upgrade to a supported release after compatibility testing.'},
    {title:'Database Port Exposed',severity:'High',asset:'192.168.56.20',description:'The database listener on port 3306 is reachable across the laboratory segment.',recommendation:'Allow database access only from required application hosts.'},
    {title:'Missing Content Security Policy',severity:'Medium',asset:'192.168.56.10',description:'The web response does not define a Content-Security-Policy header.',recommendation:'Deploy and test a restrictive Content-Security-Policy.'},
    {title:'Missing HSTS Header',severity:'Medium',asset:'192.168.56.10',description:'HTTPS responses do not instruct browsers to require encrypted connections.',recommendation:'Enable Strict-Transport-Security after validating HTTPS coverage.'},
    {title:'SMB Service Exposed',severity:'Medium',asset:'192.168.56.30',description:'SMB is reachable from systems that do not require file-sharing access.',recommendation:'Restrict SMB at the host firewall and require modern SMB signing.'},
    {title:'Self-Signed TLS Certificate',severity:'Medium',asset:'192.168.56.50',description:'The simulated TLS certificate is self-signed and cannot establish trusted identity.',recommendation:'Install a certificate issued by the approved organizational CA.'},
    {title:'Verbose Server Banner',severity:'Low',asset:'192.168.56.10',description:'The HTTP banner reveals detailed product and version information.',recommendation:'Reduce banner detail and keep the underlying service patched.'},
    {title:'Unnecessary Open Service',severity:'Low',asset:'192.168.56.40',description:'SSH is listening even though remote administration is not documented for this host.',recommendation:'Confirm the business need and disable services that are not required.'},
  ] as DemoFinding[],
  traffic: [
    {name:'HTTPS',value:38,color:'#159d70'},
    {name:'HTTP',value:22,color:'#3f7fc4'},
    {name:'DNS',value:15,color:'#7d68bd'},
    {name:'SSH',value:10,color:'#e2a146'},
    {name:'SMB',value:8,color:'#dd6575'},
    {name:'Other',value:7,color:'#7c918a'},
  ],
  alerts: [
    {title:'Repeated connection failures',severity:'High',status:'Investigating'},
    {title:'Unexpected port opened',severity:'High',status:'New'},
    {title:'Excessive DNS requests',severity:'Medium',status:'New'},
    {title:'Network traffic spike',severity:'Medium',status:'Acknowledged'},
    {title:'Self-signed TLS certificate detected',severity:'Medium',status:'Open'},
  ],
  assessment: {
    score: 68,
    riskLevel: 'Elevated',
    controls: [
      {name:'Firewall Configuration',status:'Implemented'},
      {name:'Multi-Factor Authentication',status:'Partially Implemented'},
      {name:'Incident Response Plan',status:'Not Implemented'},
      {name:'Regular Backups',status:'Implemented'},
      {name:'Centralized Logging',status:'Not Implemented'},
    ],
  },
  recommendations: [
    'Create an incident-response plan',
    'Enable multi-factor authentication',
    'Implement centralized logging',
    'Disable insecure network services',
  ],
} as const

