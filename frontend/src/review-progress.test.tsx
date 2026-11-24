// @vitest-environment jsdom
import {describe,it,expect} from 'vitest';
import {summarizeReview, ReviewProgress} from './main';
import {render,cleanup,screen} from '@testing-library/react';
describe('resumen de revisión por registro',()=>{
 it('distingue procesados, en espera, atención y locales sin contar segmentos',()=>{
  expect(summarizeReview({received:16,states:[{state:'live',records:4,segments:20},{state:'inconclusive',records:2},{state:'in_progress',records:1},{state:'pending',records:3},{state:'failed',records:2},{state:'unknown',records:1},{state:'local',records:1},{state:'stopped',records:2}]})).toEqual({total:16,reviewed:6,inconclusive:2,processing:1,waiting:3,attention:3,failed:2,blocked:0,stopped:2,local:1});
 });
 it('muestra el spinner mientras hay procesamiento o espera',()=>{
  const {container,rerender}=render(<ReviewProgress label="Todos" data={{received:2,states:[{state:'in_progress',records:1},{state:'pending',records:1}]}}/>);
  expect(screen.getByRole('status').textContent).toContain('1 en proceso');expect(container.querySelector('.review-spinner')).not.toBeNull();
  rerender(<ReviewProgress label="Todos" data={{received:2,states:[{state:'pending',records:2}]}}/>);
  expect(screen.getByRole('status').textContent).toContain('En espera');expect(container.querySelector('.review-spinner')).not.toBeNull();
  rerender(<ReviewProgress label="Todos" data={{received:2,states:[{state:'live',records:2}]}}/>);expect(container.querySelector('.review-spinner')).toBeNull();cleanup();
 });
 it('presenta cero para un lote vacío' ,()=>{expect(summarizeReview({received:0,states:[]})).toEqual({total:0,reviewed:0,inconclusive:0,processing:0,waiting:0,attention:0,failed:0,blocked:0,stopped:0,local:0});});
});
