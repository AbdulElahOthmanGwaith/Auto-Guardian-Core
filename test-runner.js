const { chromium } = require('@playwright/test');

async function testDashboard() {
  console.log('🧪 بدء اختبار لوحة التحكم...\n');
  
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  
  let testsPassed = 0;
  let testsFailed = 0;
  
  // Collect console errors
  const consoleErrors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });
  
  try {
    // Test 1: Dashboard loads
    console.log('📋 اختبار 1: تحميل لوحة التحكم...');
    await page.goto('file:///workspace/auto-guardian-docs/dashboard/index.html');
    await page.waitForLoadState('domcontentloaded');
    
    const title = await page.title();
    console.log(`   ✅ عنوان الصفحة: ${title}`);
    testsPassed++;
    
    // Test 2: Main elements exist
    console.log('\n📋 اختبار 2: التحقق من العناصر الرئيسية...');
    
    const dashboard = await page.locator('.dashboard').isVisible();
    const sidebar = await page.locator('.sidebar').isVisible();
    const header = await page.locator('.header').isVisible();
    const stats = await page.locator('.stats-grid').isVisible();
    
    if (dashboard && sidebar && header && stats) {
      console.log('   ✅ جميع العناصر الرئيسية موجودة');
      testsPassed++;
    } else {
      console.log('   ❌ بعض العناصر مفقودة');
      testsFailed++;
    }
    
    // Test 3: Stats cards
    console.log('\n📋 اختبار 3: بطاقات الإحصائيات...');
    const statCards = await page.locator('.stat-card').count();
    if (statCards === 4) {
      console.log(`   ✅ 4 بطاقات إحصائيات موجودة`);
      testsPassed++;
    } else {
      console.log(`   ❌ عدد البطاقات: ${statCards} (متوقع: 4)`);
      testsFailed++;
    }
    
    // Test 4: Charts
    console.log('\n📋 اختبار 4: الرسوم البيانية...');
    const areaChart = await page.locator('.area-chart').isVisible();
    const donutChart = await page.locator('.donut-chart').isVisible();
    const donutTotal = await page.locator('#donutTotal').textContent();
    
    if (areaChart && donutChart) {
      console.log(`   ✅ الرسوم البيانية ظاهرة (الإجمالي: ${donutTotal})`);
      testsPassed++;
    } else {
      console.log('   ❌ الرسوم البيانية غير ظاهرة');
      testsFailed++;
    }
    
    // Test 5: Navigation
    console.log('\n📋 اختبار 5: قائمة التنقل...');
    const navItems = await page.locator('.nav-item').count();
    console.log(`   ✅ ${navItems} عنصر في قائمة التنقل`);
    testsPassed++;
    
    // Test 6: Settings panel
    console.log('\n📋 اختبار 6: لوحة الإعدادات...');
    await page.click('[data-view="settings"]');
    await page.waitForTimeout(500);
    const settingsActive = await page.locator('#settingsPanel').getAttribute('class');
    
    if (settingsActive.includes('active')) {
      console.log('   ✅ لوحة الإعدادات تفتح بشكل صحيح');
      testsPassed++;
    } else {
      console.log('   ❌ لوحة الإعدادات لا تفتح');
      testsFailed++;
    }
    
    // Test 7: Issues list
    console.log('\n📋 اختبار 7: قائمة المشاكل...');
    const issuesList = await page.locator('.issues-list').isVisible();
    const issueItems = await page.locator('.issue-item').count();
    
    if (issuesList && issueItems > 0) {
      console.log(`   ✅ قائمة المشاكل ظاهرة (${issueItems} مشكلة)`);
      testsPassed++;
    } else {
      console.log('   ❌ قائمة المشاكل غير ظاهرة');
      testsFailed++;
    }
    
    // Test 8: Repositories list
    console.log('\n📋 اختبار 8: قائمة المستودعات...');
    const reposList = await page.locator('.repos-list').isVisible();
    const repoItems = await page.locator('.repo-item').count();
    
    if (reposList && repoItems > 0) {
      console.log(`   ✅ قائمة المستودعات ظاهرة (${repoItems} مستودع)`);
      testsPassed++;
    } else {
      console.log('   ❌ قائمة المستودعات غير ظاهرة');
      testsFailed++;
    }
    
    // Test 9: Search functionality
    console.log('\n📋 اختبار 9: وظيفة البحث...');
    await page.fill('#searchInput', 'auth');
    await page.waitForTimeout(300);
    const searchResults = await page.locator('.search-results').getAttribute('class');
    
    if (searchResults.includes('active')) {
      console.log('   ✅ البحث يعمل بشكل صحيح');
      testsPassed++;
    } else {
      console.log('   ❌ البحث لا يعمل');
      testsFailed++;
    }
    
    // Test 10: Toast notifications
    console.log('\n📋 اختبار 10: إشعارات Toast...');
    const toastContainer = await page.locator('.toast-container').isVisible();
    if (toastContainer) {
      console.log('   ✅ حاوية الإشعارات موجودة');
      testsPassed++;
    } else {
      console.log('   ❌ حاوية الإشعارات غير موجودة');
      testsFailed++;
    }
    
  } catch (error) {
    console.error('\n❌ حدث خطأ أثناء الاختبار:', error.message);
    testsFailed++;
  } finally {
    await browser.close();
  }
  
  // Print results
  console.log('\n' + '='.repeat(50));
  console.log('📊 نتائج الاختبار:');
  console.log('='.repeat(50));
  console.log(`✅ اختبارات ناجحة: ${testsPassed}`);
  console.log(`❌ اختبارات فاشلة: ${testsFailed}`);
  console.log(`📝 إجمالي الاختبارات: ${testsPassed + testsFailed}`);
  
  if (consoleErrors.length > 0) {
    console.log('\n⚠️ أخطاء في Console:');
    consoleErrors.forEach((err, i) => console.log(`   ${i+1}. ${err}`));
  } else {
    console.log('\n✅ لا توجد أخطاء في Console');
  }
  
  console.log('='.repeat(50));
  
  return testsFailed === 0;
}

testDashboard().then(success => {
  process.exit(success ? 0 : 1);
});
