// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { Knowledge, RecordReview } from './main';
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  HTMLDialogElement.prototype.showModal = function () {this.setAttribute("open", "");};
  HTMLDialogElement.prototype.close = function () {this.removeAttribute("open");};
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const ok = (data: unknown) => ({ok:true,json:async()=>data});
it('pagina registros sin acumular filas y permite volver', async () => {
  vi.stubGlobal('fetch',vi.fn(async (url: string) => {
    if(url.includes('/review-batches')) return ok({items:[]});
    if(url.includes('/coverage')) return ok({received:26,states:[],costs:{}});
    if(url.includes('/records?')) return ok(url.includes('cursor=next') ? {items:[{id:'b',service:'servicio',parser:'json',coverage_state:'pending',received_at:'2026-11-12T12:00:00Z',safe_text:'segunda página',completed_segments:0,segments:1}],next_cursor:null} : {items:[{id:'a',service:'servicio',parser:'json',coverage_state:'pending',received_at:'2026-11-12T12:00:00Z',safe_text:'primera página',completed_segments:0,segments:1}],next_cursor:'next'});
    return ok({});
  }));
  render(<RecordReview refresh={0}/>);
  expect(await screen.findByText('primera página')).toBeTruthy();
  const nav=screen.getByRole('navigation',{name:'Páginas de registros'});
  fireEvent.click(within(nav).getByRole('button',{name:'Siguiente'}));
  expect(await screen.findByText('segunda página')).toBeTruthy();
  expect(screen.queryByText('primera página')).toBeNull();
  fireEvent.click(within(nav).getByRole('button',{name:'Anterior'}));
  expect(await screen.findByText('primera página')).toBeTruthy();
});
it('pagina documentos y prepara la versión con documentos fuera de la página', async () => {
  const docs=Array.from({length:101},(_,i)=>({id:`d${i+1}`,title:`Documento ${i+1}`,revision:1,kind:'guide',state:'ready'}));
  let manifest: {document_id:string}[]=[];
  vi.stubGlobal('fetch',vi.fn(async (url:string,init?:RequestInit)=>{
    if(url.includes('/knowledge/builds') && init?.method==='POST'){manifest=JSON.parse(String(init.body)).manifest;return ok({build_id:'build'});}
    if(url.includes('/knowledge?')) return ok({items:url.includes('cursor=next')?docs.slice(100):docs.slice(0,100),next_cursor:url.includes('cursor=next')?null:'next',active:{version:1,active_corpus_id:'active'},builds:[]});
    return ok({revisions:[]});
  }));
  render(<Knowledge refresh={0}/>);
  expect(await screen.findByRole('button',{name:/^Documento 1$/})).toBeTruthy();
  const nav=screen.getByRole('navigation',{name:'Páginas de conocimiento'});
  fireEvent.click(within(nav).getByRole('button',{name:'Siguiente'}));
  expect(await screen.findByRole('button',{name:/^Documento 11$/})).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Preparar versión'}));
  await waitFor(()=>expect(manifest).toHaveLength(101));
  expect(manifest.some(d=>d.document_id==='d101')).toBe(true);
});
import { EventList } from './main';
it('eventos se presentan en tabla con nivel y paginación por cursor', async () => {
  const firstPage=[{id:'e1',event_time:'2026-11-12T12:00:00Z',ingested_at:'2026-11-12T12:00:01Z',event_type:'auth.failed',level:'error',service:'OpenSSH',message:'primer evento',source:'sintética',parser:'sentinel-json',selected_for_analysis:true}];
  const secondPage=[{...firstPage[0],id:'e2',message:'segundo evento',level:'warning'}];
  vi.stubGlobal('fetch',vi.fn(async (url: string) => url.includes('/services') ? ok({items:[],next_cursor:null,total_count:0}) : ok(url.includes('cursor=next') ? {items:secondPage,next_cursor:null,total_count:2} : {items:firstPage,next_cursor:'next',total_count:2})));
  render(<EventList refresh={0}/>);
  expect((await screen.findAllByText('primer evento')).length).toBeGreaterThan(0);
  expect(screen.getByRole('columnheader',{name:'Nivel'})).toBeTruthy();
  expect(screen.getByText('error')).toBeTruthy();
  const nav=screen.getByRole('navigation',{name:'Páginas de eventos'});
  fireEvent.click(within(nav).getByRole('button',{name:'Siguiente'}));
  expect((await screen.findAllByText('segundo evento')).length).toBeGreaterThan(0);
  expect(screen.queryByText('primer evento')).toBeNull();
  fireEvent.click(within(nav).getByRole('button',{name:'Anterior'}));
  expect((await screen.findAllByText('primer evento')).length).toBeGreaterThan(0);
});
it('conocimiento se crea en un modal y guarda el servicio asociado', async () => {
  let created: Record<string, unknown> | null = null;
  vi.stubGlobal('fetch',vi.fn(async (url: string, init?: RequestInit) => {
    if(url.includes('/knowledge') && init?.method==='POST' && !url.includes('builds')){created=JSON.parse(String(init.body));return ok({id:'doc-1',revision:1});}
    if(url.includes('/knowledge?')) return ok({items:[],next_cursor:null,active:{version:1,active_corpus_id:'corpus'},builds:[]});
    if(url.includes('/services')) return ok({items:[{id:'svc-1',name:'OpenSSH',enabled:true}],next_cursor:null,total_count:1});
    return ok({});
  }));
  render(<Knowledge refresh={0}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Nuevo documento'}));
  const dialog=await screen.findByRole('dialog');
  fireEvent.change(within(dialog).getByRole('textbox',{name:'Título'}),{target:{value:'Guía SSH'}});
  fireEvent.change(within(dialog).getByRole('textbox',{name:'Texto del documento'}),{target:{value:'Texto de la guía'}});
  fireEvent.pointerDown(within(dialog).getByRole('combobox',{name:'Servicio asociado'}));
  fireEvent.click(within(dialog).getByRole('combobox',{name:'Servicio asociado'}));
  fireEvent.click(await screen.findByRole('option',{name:'OpenSSH'}));
  fireEvent.click(within(dialog).getByRole('button',{name:'Guardar borrador'}));
  await waitFor(()=>expect(created).toMatchObject({title:'Guía SSH',service_id:'svc-1'}));
  await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
});
it('eventos filtra por tipo usando la API', async () => {
  const urls: string[] = [];
  vi.stubGlobal('fetch',vi.fn(async (url: string) => {urls.push(url); return url.includes('/services') ? ok({items:[],next_cursor:null,total_count:0}) : ok({items:[],next_cursor:null,total_count:0});}));
  render(<EventList refresh={0}/>);
  fireEvent.pointerDown(screen.getByRole('combobox',{name:'Tipo de evento'}));
  fireEvent.click(screen.getByRole('combobox',{name:'Tipo de evento'}));
  fireEvent.click(await screen.findByRole('option',{name:'Fallos de autenticación'}));
  await waitFor(()=>expect(urls.some(u=>u.includes('event_type=auth.failed'))).toBe(true));
});
it('las versiones del corpus se muestran en tabla con paginación y filtro por estado', async () => {
  const builds = Array.from({length: 12}, (_, i) => ({id: `v${String(i + 1).padStart(7, '0')}-corpus`, state: i < 9 ? 'ready' : i < 11 ? 'building' : 'failed', reason: i === 11 ? 'indexing_failed' : null, dimension: 384, documents: 3, vectors: 42, created_at: '2026-11-20T10:00:00Z', embedding_model_revision: 'e5-small'}));
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.includes('/knowledge?')) return ok({items: [], next_cursor: null, active: {version: 1, active_corpus_id: builds[0].id}, builds});
    if (url.includes('/services')) return ok({items: []});
    return ok({revisions: []});
  }));
  render(<Knowledge refresh={0}/>);
  expect(await screen.findByText('12 versiones · Página 1 de 2')).toBeTruthy();
  expect(screen.getByText('Activa')).toBeTruthy();
  expect(screen.getByText('v0000001…')).toBeTruthy();
  expect(screen.queryByText('v0000012…')).toBeNull();
  const nav = screen.getByRole('navigation', {name: 'Páginas de versiones del corpus'});
  fireEvent.click(within(nav).getByRole('button', {name: 'Siguiente'}));
  expect(await screen.findByText('12 versiones · Página 2 de 2')).toBeTruthy();
  expect(screen.getByText('v0000012…')).toBeTruthy();
  fireEvent.pointerDown(screen.getByRole('combobox', {name: 'Estado'}));
  fireEvent.click(screen.getByRole('combobox', {name: 'Estado'}));
  fireEvent.click(await screen.findByRole('option', {name: 'Fallida'}));
  expect(await screen.findByText('1 versiones · Página 1 de 1')).toBeTruthy();
  expect(screen.getByText('indexing_failed')).toBeTruthy();
});
