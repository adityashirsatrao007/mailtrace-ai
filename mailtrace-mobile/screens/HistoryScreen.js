import { useState, useEffect } from 'react'
import { View, Text, FlatList, RefreshControl } from 'react-native'
import { Ionicons } from '@expo/vector-icons'

const API = 'http://192.168.1.10:8001'

export default function HistoryScreen() {
  const [scans, setScans] = useState([])
  const [refreshing, setRefreshing] = useState(false)

  const load = async () => {
    try {
      const res = await fetch(`${API}/api/v1/dashboard`)
      const data = await res.json()
      setScans(data.recent_scans || [])
    } catch { setScans([]) }
  }

  useEffect(() => { load() }, [])

  const onRefresh = async () => {
    setRefreshing(true)
    await load()
    setRefreshing(false)
  }

  const renderItem = ({ item }) => (
    <View style={{ backgroundColor: '#0f172a', borderRadius: 12, padding: 14, marginBottom: 8, borderWidth: 1, borderColor: '#1e293b' }}>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <View style={{ flex: 1 }}>
          <Text style={{ color: '#f1f5f9', fontSize: 13, fontWeight: '500' }} numberOfLines={1}>{item.subject}</Text>
          <Text style={{ color: '#64748b', fontSize: 11, marginTop: 3 }}>{item.from}</Text>
          <Text style={{ color: '#475569', fontSize: 10, marginTop: 3 }}>{item.at}</Text>
        </View>
        <View style={{ alignItems: 'flex-end', marginLeft: 10 }}>
          <View style={{ backgroundColor: item.threat_level === 'CRITICAL' ? '#dc262622' : item.threat_level === 'HIGH' ? '#f9731622' : item.threat_level === 'MEDIUM' ? '#eab30822' : '#22c55e22', paddingHorizontal: 8, paddingVertical: 3, borderRadius: 8, marginBottom: 4 }}>
            <Text style={{ color: item.threat_level === 'CRITICAL' ? '#ef4444' : item.threat_level === 'HIGH' ? '#f97316' : item.threat_level === 'MEDIUM' ? '#eab308' : '#22c55e', fontSize: 9, fontWeight: 'bold' }}>{item.threat_level}</Text>
          </View>
          <Text style={{ color: '#94a3b8', fontSize: 11 }}>{item.score?.toFixed(0)}%</Text>
        </View>
      </View>
    </View>
  )

  return (
    <View style={{ backgroundColor: '#030712', flex: 1, padding: 20 }}>
      <Text style={{ color: '#f1f5f9', fontSize: 18, fontWeight: 'bold', marginBottom: 4 }}>Scan History</Text>
      <Text style={{ color: '#64748b', fontSize: 12, marginBottom: 16 }}>{scans.length} recent scans</Text>
      <FlatList
        data={scans}
        renderItem={renderItem}
        keyExtractor={(item, i) => i.toString()}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#00ff88" />}
        ListEmptyComponent={<Text style={{ color: '#475569', textAlign: 'center', marginTop: 60 }}>No scans yet</Text>}
      />
    </View>
  )
}
