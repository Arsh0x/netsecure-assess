import {Navigate,Route,Routes} from 'react-router-dom'
import Layout from './components/Layout'
import {useAuth} from './lib/auth'
import {Spinner} from './components/ui'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import DemoPage from './pages/DemoPage'
import Projects from './pages/Projects'
import ProjectDetail from './pages/ProjectDetail'
import Assets from './pages/Assets'
import AssetDetail from './pages/AssetDetail'
import Scans from './pages/Scans'
import NewScan from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'
import Findings from './pages/Findings'
import FindingDetail from './pages/FindingDetail'
import Traffic from './pages/Traffic'
import Alerts from './pages/Alerts'
import Assessments from './pages/Assessments'
import AssessmentDetail from './pages/AssessmentDetail'
import Reports from './pages/Reports'
import {Admin,Ethics,Help} from './pages/InfoPages'

function Protected(){
  const {user,loading}=useAuth()
  if(loading)return <Spinner/>
  return user?<Layout/>:<Navigate to="/login" replace/>
}

export default function App(){
  return <Routes>
    <Route path="/login" element={<Login/>}/>
    <Route element={<Protected/>}>
      <Route path="/dashboard" element={<Dashboard/>}/>
      <Route path="/demo" element={<DemoPage/>}/>
      <Route path="/projects" element={<Projects/>}/>
      <Route path="/projects/:id" element={<ProjectDetail/>}/>
      <Route path="/assets" element={<Assets/>}/>
      <Route path="/assets/:id" element={<AssetDetail/>}/>
      <Route path="/scans" element={<Scans/>}/>
      <Route path="/scans/new" element={<NewScan/>}/>
      <Route path="/scans/:id" element={<ScanDetail/>}/>
      <Route path="/findings" element={<Findings/>}/>
      <Route path="/findings/:id" element={<FindingDetail/>}/>
      <Route path="/traffic" element={<Traffic/>}/>
      <Route path="/alerts" element={<Alerts/>}/>
      <Route path="/assessments" element={<Assessments/>}/>
      <Route path="/assessments/:id" element={<AssessmentDetail/>}/>
      <Route path="/reports" element={<Reports/>}/>
      <Route path="/admin" element={<Admin/>}/>
      <Route path="/help" element={<Help/>}/>
      <Route path="/ethics" element={<Ethics/>}/>
    </Route>
    <Route path="*" element={<Navigate to="/dashboard" replace/>}/>
  </Routes>
}

