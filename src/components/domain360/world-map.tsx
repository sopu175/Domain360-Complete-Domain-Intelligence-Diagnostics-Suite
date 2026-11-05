'use client';

import 'leaflet/dist/leaflet.css';
import { MapContainer, TileLayer, CircleMarker, Tooltip } from 'react-leaflet';
import type { GeoNode, NetworkNode } from '@/lib/domain360/impl/propagation-geo';

export interface MapPin {
  id: string;
  lat: number;
  lon: number;
  kind: 'geo' | 'network';
  status: string;
  title: string;
  subtitle: string;
  values: string | null;
}

export function pinColor(status: string, kind: 'geo' | 'network'): string {
  if (kind === 'geo') {
    if (status === 'resolved') return '#10b981';
    if (status === 'empty') return '#a1a1aa';
    return '#ef4444';
  }
  if (status === 'healthy') return '#0d9488';
  if (status === 'warning') return '#f59e0b';
  if (status === 'not_configured') return '#a1a1aa';
  return '#ef4444';
}

export default function WorldMap({ pins }: { pins: MapPin[] }) {
  return (
    <div className="h-[340px] w-full overflow-hidden rounded-lg border sm:h-[400px]">
      <MapContainer
        center={[28, 15]}
        zoom={2}
        minZoom={1}
        maxZoom={10}
        scrollWheelZoom={false}
        worldCopyJump
        style={{ height: '100%', width: '100%', background: '#dbeafe' }}
        attributionControl
      >
        <TileLayer
          attribution='Tiles &copy; Esri — Source: Esri, Maxar, Earthstar Geographics | Data &copy; OpenStreetMap contributors'
          url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}"
          maxZoom={16}
        />
        {pins.map((pin) => (
          <CircleMarker
            key={pin.id}
            center={[pin.lat, pin.lon]}
            radius={pin.kind === 'geo' ? 7 : 5}
            pathOptions={{
              color: '#ffffff',
              weight: 1.5,
              fillColor: pinColor(pin.status, pin.kind),
              fillOpacity: 0.95,
              dashArray: pin.kind === 'network' ? '2 2' : undefined,
            }}
          >
            <Tooltip direction="top" offset={[0, -6]} opacity={1}>
              <div className="text-[11px] leading-snug">
                <p className="font-semibold">{pin.title}</p>
                <p className="text-muted-foreground">{pin.subtitle}</p>
                <p className="mt-0.5 font-mono">{pin.values || 'No answer'}</p>
              </div>
            </Tooltip>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}
