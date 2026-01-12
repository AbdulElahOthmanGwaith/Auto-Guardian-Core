import { test, expect } from '@playwright/test';

test.describe('Auto-Guardian Dashboard Tests', () => {
  
  test('Dashboard loads successfully', async ({ page }) => {
    // Navigate to dashboard
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Check page title
    await expect(page).toHaveTitle(/Auto-Guardian/);
    
    // Check main elements exist
    await expect(page.locator('.dashboard')).toBeVisible();
    await expect(page.locator('.sidebar')).toBeVisible();
    await expect(page.locator('.main-content')).toBeVisible();
    await expect(page.locator('.header')).toBeVisible();
  });

  test('Stats cards are visible', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Check all 4 stat cards exist
    const statCards = page.locator('.stat-card');
    await expect(statCards).toHaveCount(4);
    
    // Verify stat values are displayed
    await expect(page.locator('#statThreats')).toBeVisible();
    await expect(page.locator('#statSuccess')).toBeVisible();
    await expect(page.locator('#statOpen')).toBeVisible();
    await expect(page.locator('#statResponse')).toBeVisible();
  });

  test('Charts render correctly', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Check charts section
    await expect(page.locator('.charts-section')).toBeVisible();
    await expect(page.locator('.area-chart')).toBeVisible();
    await expect(page.locator('.donut-chart')).toBeVisible();
    
    // Check donut chart elements
    await expect(page.locator('.donut-svg')).toBeVisible();
    await expect(page.locator('#donutTotal')).toContainText(/\d+/);
  });

  test('Navigation menu works', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Check nav items exist
    const navItems = page.locator('.nav-item');
    await expect(navItems).toHaveCount(6);
    
    // Test clicking settings
    await page.click('[data-view="settings"]');
    await expect(page.locator('#settingsPanel')).toHaveClass(/active/);
  });

  test('Search functionality works', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Type in search box
    await page.fill('#searchInput', 'auth');
    
    // Check search results appear
    await expect(page.locator('.search-results')).toHaveClass(/active/);
  });

  test('Settings panel interactions', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Open settings
    await page.click('#settingsNavItem');
    await expect(page.locator('#settingsPanel')).toHaveClass(/active/);
    
    // Fill settings
    await page.fill('#settingUsername', 'Test User');
    await page.fill('#settingEmail', 'test@example.com');
    
    // Save settings
    await page.click('.save-btn');
    
    // Check toast notification appears
    await expect(page.locator('.toast')).toBeVisible();
  });

  test('Issues list renders', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Check issues section
    await expect(page.locator('.issues-list')).toBeVisible();
    
    // Check issue items exist
    const issueItems = page.locator('.issue-item');
    await expect(issueItems.first()).toBeVisible();
  });

  test('Repositories list renders', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Check repos section
    await expect(page.locator('.repos-list')).toBeVisible();
    
    // Check repo items exist
    const repoItems = page.locator('.repo-item');
    await expect(repoItems.first()).toBeVisible();
  });

  test('Responsive design elements', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    
    // Check stats grid
    await expect(page.locator('.stats-grid')).toBeVisible();
    
    // Check activity section
    await expect(page.locator('.activity-section')).toBeVisible();
  });

});

test.describe('Setup Guide Tests', () => {
  
  test('Setup guide loads successfully', async ({ page }) => {
    await page.goto('file:///workspace/auto-guardian-docs/setup-guide.html');
    
    // Check page content
    await expect(page.locator('body')).toBeVisible();
    await expect(page.locator('h1')).toBeVisible();
  });

});
