import {render,screen} from '@testing-library/react'
import {describe,expect,it} from 'vitest'
import {RiskBadge,Severity,Status} from './ui'

describe('security labels',()=>{
  it('renders severity and normalized workflow status',()=>{
    render(<><Severity value="High"/><Status value="in_progress"/></>)
    expect(screen.getByText('High')).toHaveClass('severity-high')
    expect(screen.getByText('in progress')).toBeInTheDocument()
  })
  it('maps numeric risk into an understandable band',()=>{
    render(<RiskBadge score={82}/>)
    expect(screen.getByText(/critical/i)).toHaveClass('risk-critical')
  })
})

