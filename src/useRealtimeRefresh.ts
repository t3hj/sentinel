import { useEffect, useRef } from 'react'
import { supabase } from './lib/supabase'

export function useRealtimeRefresh(onRefresh: () => void) {
  const refreshRef = useRef(onRefresh)
  refreshRef.current = onRefresh

  useEffect(() => {
    const channel = supabase
      .channel('sentinel-security-updates')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'security_events' }, () => refreshRef.current())
      .on('postgres_changes', { event: '*', schema: 'public', table: 'incidents' }, () => refreshRef.current())
      .subscribe()

    return () => {
      void supabase.removeChannel(channel)
    }
  }, [])
}
