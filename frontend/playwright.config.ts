import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',workers:1,timeout:240000,use:{baseURL:'http://localhost:8080',headless:true},reporter:[['list'],['json',{outputFile:(process.env.UI_ARTIFACT_DIR||'../artifacts/validation')+'/playwright-results.json'}]],outputDir:'../artifacts/private/playwright-results'});
