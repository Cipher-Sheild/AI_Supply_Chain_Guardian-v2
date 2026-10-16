const path=require('node:path');
const {runTests}=require('@vscode/test-electron');
runTests({
  ...(process.env.GUARDIAN_TEST_CODE ? {vscodeExecutablePath:process.env.GUARDIAN_TEST_CODE} : {}),
  version:'1.95.3',
  extensionDevelopmentPath:path.resolve(__dirname,'..'),
  extensionTestsPath:path.resolve(__dirname,'suite.cjs'),
  launchArgs:['--no-sandbox','--disable-gpu','--skip-welcome','--skip-release-notes','--disable-workspace-trust'],
}).catch(error=>{console.error(error);process.exit(1);});
