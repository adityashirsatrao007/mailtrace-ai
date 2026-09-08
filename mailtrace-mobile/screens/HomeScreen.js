import { useState, useEffect, useRef } from 'react'
import { View, Text, ScrollView, TouchableOpacity, RefreshControl, Alert, Platform } from 'react-native'
import { Ionicons } from '@expo/vector-icons'
import * as Notifications from 'expo-notifications'
import * as Device from 'expo-device'

const API = 'http://192.168.1.10:8001'

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
})

async function registerForPushNotifications() {
  if (!Device.isDevice) {
    Alert.alert('Warning', 'Push notifications require a physical device')
    return null
  }
  const { status: existingStatus } = await Notifications.getPermissionsAsync()
  let finalStatus = existingStatus
  if (existingStatus !== 'granted') {
    const { status } = await Notifications.requestPermissionsAsync()
    finalStatus = status
  }
  if (finalStatus !== 'granted') {
    Alert.alert('Permission denied', 'Enable notifications in settings')
    return null
  }
  const token = (await Notifications.getExpoPushTokenAsync()).data
  return token
}

export default function HomeScreen() {
  const [stats, setStats] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [pushToken, setPushToken] = useState(null)
  const [notificationsEnabled, setNotificationsEnabled] = useState(false)
  const lastNotificationResponse = Notifications.useLastNotificationResponse()
  const responseListener = useRef()

  useEffect(() => {
    load()
    registerForPushNotifications().then(token => {
      if (token) setPushToken(token)
    })
    responseListener.current = Notifications.addNotificationResponseReceivedListener(response => {
      const data = response.notification.request.content.data
      if (data?.screen) {
        Alert.alert('Threat Alert', data.message || 'New threat detected')
      }
    })
    return () => {
      if (responseListener.current) Notifications.removeNotificationSubscription(responseListener.current)
    }
  }, [])

  useEffect(() => {
    if (lastNotificationResponse?.notification?.request?.content?.data?.screen) {
      Alert.alert('Threat Alert', lastNotificationResponse.notification.request.content.data.message || 'New threat detected')
    }
  }, [lastNotificationResponse])

  const load = async () => {
    try {
      const res = await fetch(`${API}/api/v1/dashboard`)
      setStats(await res.json())
    } catch { setStats(null) }
  }

  const onRefresh = async () => {
    setRefreshing(true)
    await load()
    setRefreshing(false)
  }

  const toggleNotifications = async () => {
    if (!notificationsEnabled) {
      const token = await registerForPushNotifications()
      if (token) {
        setPushToken(token)
        setNotificationsEnabled(true)
        Alert.alert('Enabled', 'You will receive alerts for critical threats')
        // Register token with backend
        try {
          await fetch(`${API}/api/v1/notifications/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, platform: Platform.OS }),
          })
        } catch {}
      }
    } else {
      setNotificationsEnabled(false)
      Alert.alert('Disabled', 'Threat alerts disabled')
    }
  }

  return (
    <ScrollView style={{ backgroundColor: '#030712', flex: 1 }} refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#00ff88" />}>
      <View style={{ padding: 20 }}>
        <Text style={{ color: '#00ff88', fontSize: 24, fontWeight: 'bold', marginBottom: 4 }}>MailTrace AI</Text>
        <Text style={{ color: '#64748b', fontSize: 13, marginBottom: 24 }}>Threat Monitoring Dashboard</Text>

        {/* Notifications Toggle */}
        <TouchableOpacity
          onPress={toggleNotifications}
          style={{ backgroundColor: notificationsEnabled ? '#00ff8815' : '#0f172a', borderRadius: 12, padding: 14, marginBottom: 16, borderWidth: 1, borderColor: notificationsEnabled ? '#00ff8830' : '#1e293b', flexDirection: 'row', alignItems: 'center' }}
        >
          <Ionicons name={notificationsEnabled ? 'notifications' : 'notifications-off'} size={20} color={notificationsEnabled ? '#00ff88' : '#475569'} />
          <View style={{ marginLeft: 12, flex: 1 }}>
            <Text style={{ color: '#f1f5f9', fontSize: 13, fontWeight: '500' }}>
              {notificationsEnabled ? 'Threat Alerts Active' : 'Enable Threat Alerts'}
            </Text>
            <Text style={{ color: '#64748b', fontSize: 11, marginTop: 2 }}>
              {notificationsEnabled ? 'Push notifications for critical threats' : 'Get notified of critical phishing threats'}
            </Text>
          </View>
          <View style={{ width: 44, height: 24, borderRadius: 12, backgroundColor: notificationsEnabled ? '#00ff88' : '#1e293b', justifyContent: 'center', paddingHorizontal: 2 }}>
            <View style={{ width: 20, height: 20, borderRadius: 10, backgroundColor: 'white', alignSelf: notificationsEnabled ? 'flex-end' : 'flex-start' }} />
          </View>
        </TouchableOpacity>

        {/* Stats */}
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 12 }}>
          {[
            { label: 'Scans', value: stats?.total_scans || 0, color: '#00bfff', icon: 'scan' },
            { label: 'Threats', value: stats?.phishing_detected || 0, color: '#ff3366', icon: 'warning' },
            { label: 'Critical', value: stats?.critical_threats || 0, color: '#ff8800', icon: 'alert-circle' },
            { label: 'Safe', value: (stats?.total_scans || 0) - (stats?.phishing_detected || 0), color: '#00ff88', icon: 'checkmark-circle' },
          ].map((s, i) => (
            <View key={i} style={{ width: '47%', backgroundColor: '#0f172a', borderRadius: 16, padding: 16, borderWidth: 1, borderColor: '#1e293b' }}>
              <Ionicons name={s.icon} size={20} color={s.color} />
              <Text style={{ color: '#f1f5f9', fontSize: 28, fontWeight: 'bold', marginTop: 8 }}>{s.value}</Text>
              <Text style={{ color: '#64748b', fontSize: 12, marginTop: 2 }}>{s.label}</Text>
            </View>
          ))}
        </View>

        {/* Recent Scans */}
        <Text style={{ color: '#f1f5f9', fontSize: 16, fontWeight: '600', marginTop: 28, marginBottom: 12 }}>Recent Scans</Text>
        {(stats?.recent_scans || []).slice(0, 5).map((scan, i) => (
          <View key={i} style={{ backgroundColor: '#0f172a', borderRadius: 12, padding: 14, marginBottom: 8, borderWidth: 1, borderColor: '#1e293b', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
            <View style={{ flex: 1 }}>
              <Text style={{ color: '#f1f5f9', fontSize: 13, fontWeight: '500' }} numberOfLines={1}>{scan.subject}</Text>
              <Text style={{ color: '#64748b', fontSize: 11, marginTop: 2 }}>{scan.from} • {scan.at}</Text>
            </View>
            <View style={{ marginLeft: 10, backgroundColor: scan.threat_level === 'CRITICAL' ? '#dc262622' : scan.threat_level === 'HIGH' ? '#f9731622' : '#22c55e22', paddingHorizontal: 10, paddingVertical: 4, borderRadius: 10 }}>
              <Text style={{ color: scan.threat_level === 'CRITICAL' ? '#ef4444' : scan.threat_level === 'HIGH' ? '#f97316' : '#22c55e', fontSize: 10, fontWeight: 'bold' }}>{scan.threat_level}</Text>
            </View>
          </View>
        ))}
      </View>
    </ScrollView>
  )
}
