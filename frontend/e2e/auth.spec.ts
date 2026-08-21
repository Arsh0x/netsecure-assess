import {expect,test} from '@playwright/test'

test('shows the authorization-first sign-in experience',async({page})=>{
  await page.goto('/login')
  await expect(page.getByRole('heading',{name:'Welcome back'})).toBeVisible()
  await expect(page.getByText('Authorized, defensive, and educational use only')).toBeVisible()
  await expect(page.getByRole('button',{name:/Enter workspace/})).toBeEnabled()
})

