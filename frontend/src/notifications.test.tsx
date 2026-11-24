// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Notifications } from './main';
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('muestra el total sin leer, marca la incidencia y la abre', async () => {
  const item={incident_id:'one',title:'Fallos de acceso',severity:'high',opened_at:'2026-11-13T09:00:00Z',read_at:null,service:'ssh'};
  const fetcher=vi.fn(async (_url:string, init?:RequestInit) => ({ok:true,json:async()=>init?.method==='POST'?{read:true}:{items:[item],unread_count:101}}));
  const onOpen=vi.fn();vi.stubGlobal('fetch',fetcher);render(<Notifications refresh={0} onOpen={onOpen}/>);
  const bell=await screen.findByLabelText('Notificaciones, 101 sin leer');
  expect(bell.textContent).toContain('99+');fireEvent.click(bell);
  fireEvent.click(screen.getByRole('button',{name:/Fallos de acceso/}));
  await waitFor(()=>expect(onOpen).toHaveBeenCalledWith('one'));
  expect(fetcher).toHaveBeenCalledWith('/api/v1/notifications/one/read',expect.objectContaining({method:'POST'}));
  expect(screen.getByLabelText('Notificaciones, 100 sin leer')).toBeTruthy();
});
it('mantiene el aviso cuando falla el marcado', async () => {
  vi.stubGlobal('fetch',vi.fn(async (_url:string,init?:RequestInit)=>init?.method==='POST'?{ok:false,json:async()=>({error:{message:'No se pudo marcar'}})}:{ok:true,json:async()=>({items:[{incident_id:'one',title:'Aviso',severity:'low',opened_at:'2026-11-13T09:00:00Z',read_at:null}],unread_count:1})}));
  const onOpen=vi.fn();render(<Notifications refresh={0} onOpen={onOpen}/>);
  fireEvent.click(await screen.findByLabelText('Notificaciones, 1 sin leer'));
  fireEvent.click(screen.getByRole('button',{name:/Aviso/}));
  expect((await screen.findByRole('alert')).textContent).toContain('No se pudo marcar');
  expect(onOpen).not.toHaveBeenCalled();
  expect(screen.getByLabelText('Notificaciones, 1 sin leer')).toBeTruthy();
});
