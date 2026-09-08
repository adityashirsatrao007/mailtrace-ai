import { useState } from 'react'
import { View, Text, TextInput, ScrollView, TouchableOpacity, Alert, ActivityIndicator } from 'react-native'
import { Ionicons } from '@expo/vector-icons'

const API = 'http://192.168.1.10:8001'

export default function ScanScreen() {
  const [emailText, setEmailText] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)

  const analyze = async () => {
    if (!emailText.trim()) return Alert.alert('Error', 'Paste an email to scan')
    setLoading(true)
    setResult(null)
    try {
      const res = await fetch(`${API}/api/v1/analyze-text`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: emailText }),
      })
      setResult(await res.json())
    } catch (e) { Alert.alert('Error', 'Backend unreachable. Check your IP.') }
    setLoading(false)
  }

  const scoreColor = result?.threat_level === 'CRITICAL' ? '#ef4444' : result?.threat_level === 'HIGH' ? '#f97316' : result?.threat_level === 'MEDIUM' ? '#eab308' : '#22c55e'

  return (
    <ScrollView style={{ backgroundColor: '#030712', flex: 1 }} contentContainerStyle={{ padding: 20 }}>
      <Text style={{ color: '#f1f5f9', fontSize: 18, fontWeight: 'bold', marginBottom: 4 }}>Analyze Email</Text>
      <Text style={{ color: '#64748b', fontSize: 12, marginBottom: 16 }}>Paste email headers or body text below</Text>

      <TextInput
        value={emailText}
        onChangeText={setEmailText}
        multiline
        numberOfLines={8}
        placeholder="Paste email content here..."
        placeholderTextColor="#475569"
        style={{ backgroundColor: '#0f172a', borderWidth: 1, borderColor: '#1e293b', borderRadius: 12, padding: 14, color: '#f1f5f9', fontSize: 13, minHeight: 160, textAlignVertical: 'top' }}
      />

      <TouchableOpacity
        onPress={analyze}
        disabled={loading}
        style={{ backgroundColor: loading ? '#1e293b' : '#00ff88', borderRadius: 12, padding: 14, flexDirection: 'row', justifyContent: 'center', alignItems: 'center', marginTop: 12 }}
      >
        {loading ? <ActivityIndicator color="#00ff88" /> : <Ionicons name="scan" size={16} color="#030712" />}
        <Text style={{ color: '#030712', fontWeight: 'bold', marginLeft: 8, fontSize: 14 }}>{loading ? 'Scanning...' : 'Run Threat Analysis'}</Text>
      </TouchableOpacity>

      {result && (
        <View style={{ marginTop: 24 }}>
          {/* Score Ring */}
          <View style={{ alignItems: 'center', marginBottom: 20 }}>
            <View style={{ width: 100, height: 100, borderRadius: 50, borderWidth: 6, borderColor: scoreColor, justifyContent: 'center', alignItems: 'center' }}>
              <Text style={{ color: scoreColor, fontSize: 28, fontWeight: 'bold' }}>{Math.round(result.threat_score * 100)}%</Text>
            </View>
            <View style={{ backgroundColor: `${scoreColor}22`, paddingHorizontal: 12, paddingVertical: 4, borderRadius: 10, marginTop: 8 }}>
              <Text style={{ color: scoreColor, fontWeight: 'bold', fontSize: 12 }}>{result.threat_level}</Text>
            </View>
          </View>

          {/* Classification */}
          <View style={{ backgroundColor: '#0f172a', borderRadius: 12, padding: 14, marginBottom: 10, borderWidth: 1, borderColor: '#1e293b' }}>
            <Text style={{ color: '#64748b', fontSize: 11, marginBottom: 4 }}>Classification</Text>
            <Text style={{ color: '#f1f5f9', fontSize: 14 }}>{(result.classification || '').replace(/_/g, ' ')}</Text>
          </View>

          {/* Anomalies */}
          {result.anomalies?.length > 0 && (
            <View style={{ backgroundColor: '#0f172a', borderRadius: 12, padding: 14, marginBottom: 10, borderWidth: 1, borderColor: '#1e293b' }}>
              <Text style={{ color: '#ef4444', fontSize: 12, fontWeight: '600', marginBottom: 6 }}>Anomalies ({result.anomalies.length})</Text>
              {result.anomalies.map((a, i) => (
                <Text key={i} style={{ color: '#94a3b8', fontSize: 12, marginBottom: 3 }}>• {a}</Text>
              ))}
            </View>
          )}

          {/* Recommendations */}
          {result.recommendations?.length > 0 && (
            <View style={{ backgroundColor: '#0f172a', borderRadius: 12, padding: 14, marginBottom: 10, borderWidth: 1, borderColor: '#1e293b' }}>
              <Text style={{ color: '#22c55e', fontSize: 12, fontWeight: '600', marginBottom: 6 }}>Recommendations</Text>
              {result.recommendations.map((r, i) => (
                <Text key={i} style={{ color: '#94a3b8', fontSize: 12, marginBottom: 3 }}>→ {r}</Text>
              ))}
            </View>
          )}

          {/* AI Narrative */}
          {result.ai_narrative && (
            <View style={{ backgroundColor: '#0f172a', borderRadius: 12, padding: 14, borderWidth: 1, borderColor: '#1e293b' }}>
              <Text style={{ color: '#00bfff', fontSize: 12, fontWeight: '600', marginBottom: 6 }}>AI Forensic Narrative</Text>
              <Text style={{ color: '#94a3b8', fontSize: 11, lineHeight: 16 }}>{result.ai_narrative}</Text>
            </View>
          )}
        </View>
      )}
    </ScrollView>
  )
}
