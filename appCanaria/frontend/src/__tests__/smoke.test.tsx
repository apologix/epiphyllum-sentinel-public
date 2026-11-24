import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';
import { Logo, Header } from '../components/ui';
import { Button } from '../components/arc/button/button';
import { Badge } from '../components/arc/badge/badge';

describe('Canario UI (componentes Arc reales + marca)', () => {
  it('el logo renderiza la marca CANARIO', () => { render(<Logo />); expect(screen.getByText('CANARIO')).toBeTruthy(); });
  it('el header enlaza al portal y a solicitar propuesta', () => { render(<MemoryRouter><Header /></MemoryRouter>); expect(screen.getByText('Portal de clientes')).toBeTruthy(); expect(screen.getByText('Solicitar propuesta')).toBeTruthy(); });
  it('Button y Badge de Arc renderizan', () => { render(<><Button>Enviar consulta</Button><Badge tone="success">activo</Badge></>); expect(screen.getByText('Enviar consulta')).toBeTruthy(); expect(screen.getByText('activo')).toBeTruthy(); });
});
