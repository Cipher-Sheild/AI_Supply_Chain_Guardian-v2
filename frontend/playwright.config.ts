import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./tests',timeout:120000,workers:1,
 use:{baseURL:process.env.GUARDIAN_UI_URL||'http://127.0.0.1:3300',trace:'off',screenshot:'off',video:'off'},
 projects:[{name:'chromium',use:{browserName:'chromium'}}]});
