// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Chat } from './main';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
describe('chat', () => {
  it('muestra espera de API a la izquierda y luego la respuesta', async () => {
    const user = { id:'question', role:'user', evidence_version:1, state:'pending', content:{question:'¿Qué pasó?'}, job:{state:'pending',reason:'rate_limit_wait', snapshot:{}} };
    let calls = 0; const fetchMock = vi.fn(async (url: string) => url.includes('chat-presence') ? {ok:true,json:async()=>({active:true})} : {ok:true,json:async()=>({items:++calls === 1 ? [user] : [{...user,state:'succeeded',job:{state:'succeeded',snapshot:{},analysis:{origin:'live'}}},{id:'answer',role:'assistant',reply_to:'question',evidence_version:1,content:{answer:'Revisá la evidencia.'}}]})});
    vi.stubGlobal('fetch', fetchMock);
    const {container,rerender}=render(<Chat id="one" evidenceVersion={1} refresh={0}/>);
    expect((await screen.findByRole('status')).textContent).toContain('Esperando disponibilidad de la API');
    expect(container.querySelector('.chat-pending .review-spinner')).not.toBeNull();
    rerender(<Chat id="one" evidenceVersion={1} refresh={1}/>);
    expect(await screen.findByText('Revisá la evidencia.')).toBeTruthy();
    expect(container.querySelector('.chat-pending')).toBeNull();
  });
  it('explica una respuesta inválida', async () => {
    vi.stubGlobal('fetch',vi.fn(async (url: string) => url.includes('chat-presence') ? {ok:true,json:async()=>({active:true})} : {ok:true,json:async()=>({items:[{id:'q',role:'user',evidence_version:1,state:'failed',content:{question:'Hola'},job:{state:'failed',reason:'invalid_provider_response'}}]})}));
    render(<Chat id="one" evidenceVersion={1} refresh={0}/>);
    expect((await screen.findByRole('alert')).textContent).toContain('respuesta válida');
  });
  it('explica la pausa sin aparentar que la pregunta sigue en cola', async () => {
    vi.stubGlobal('fetch',vi.fn(async (url: string) => url.includes('chat-presence') ? {ok:true,json:async()=>({active:true})} : {ok:true,json:async()=>({items:[{id:'q',role:'user',evidence_version:1,state:'blocked_config',content:{question:'¿Qué pasó?'},job:{state:'blocked_config',reason:'generation_paused'}}]})}));
    render(<Chat id="one" evidenceVersion={1} refresh={0}/>);
    expect((await screen.findByRole('alert')).textContent).toContain('La generación está pausada');
    expect(screen.queryByText('Tu pregunta está en cola…')).toBeNull();
  });
  it('desactiva el envío cuando la generación está pausada', async () => {
    vi.stubGlobal('fetch',vi.fn(async (url: string) => url.includes('chat-presence') ? {ok:true,json:async()=>({active:true})} : {ok:true,json:async()=>({items:[]})}));
    render(<Chat id="one" evidenceVersion={1} refresh={0} generationPaused/>);
    expect((await screen.findByText('La IA está pausada. Activá la generación para enviar preguntas.'))).toBeTruthy();
    expect((screen.getByRole('button', {name:'Enviar pregunta'}) as HTMLButtonElement).disabled).toBe(true);
  });
});
