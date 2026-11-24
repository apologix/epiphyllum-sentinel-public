// @vitest-environment jsdom
import {test,expect} from 'vitest';
import {render,screen} from '@testing-library/react';
import {SafeText} from './main';
test('corpus y salida hostil se presentan como texto inerte',()=>{const payload='<img src=x onerror="window.pwned=true"><script>alert(1)</script>';const {container}=render(<SafeText value={payload}/>);expect(screen.getByText(payload)).toBeTruthy();expect(container.querySelector('img')).toBeNull();expect(container.querySelector('script')).toBeNull();});
import {ResponseParts} from './main';
test('AnalysisResponse.evidence presenta hallazgo y evento exacto sin confundir facts',()=>{const event={id:'event-in-snapshot',message:'Credencial ficticia rechazada',event_type:'auth.failed'};const {container}=render(<ResponseParts response={{evidence:[{event_id:event.id,claim:'Intento rechazado'}],uncertainty:['Falta contexto'],recommendations:['Revisar manualmente']}} snapshot={{events:[event],chunks:[]}}/>);expect(screen.getByText('Intento rechazado')).toBeTruthy();expect(screen.getByText('Evento '+event.id)).toBeTruthy();expect(container.textContent).toContain('Credencial ficticia rechazada');expect(container.textContent).toContain('auth.failed');});
