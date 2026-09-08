import { StatusBar } from 'expo-status-bar'
import { NavigationContainer, DarkTheme } from '@react-navigation/native'
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs'
import { Ionicons } from '@expo/vector-icons'
import HomeScreen from './screens/HomeScreen'
import ScanScreen from './screens/ScanScreen'
import HistoryScreen from './screens/HistoryScreen'

const Tab = createBottomTabNavigator()

const theme = {
  ...DarkTheme,
  colors: { ...DarkTheme.colors, background: '#030712', card: '#0f172a', text: '#f1f5f9', border: '#1e293b' },
}

export default function App() {
  return (
    <NavigationContainer theme={theme}>
      <StatusBar style="light" />
      <Tab.Navigator
        screenOptions={({ route }) => ({
          tabBarIcon: ({ color, size }) => {
            const icons = { Dashboard: 'shield-checkmark', Scan: 'scan', History: 'time' }
            return <Ionicons name={icons[route.name]} size={size} color={color} />
          },
          tabBarActiveTintColor: '#00ff88',
          tabBarInactiveTintColor: '#475569',
          tabBarStyle: { backgroundColor: '#0f172a', borderTopColor: '#1e293b', paddingBottom: 4 },
          headerStyle: { backgroundColor: '#030712' },
          headerTintColor: '#f1f5f9',
        })}
      >
        <Tab.Screen name="Dashboard" component={HomeScreen} />
        <Tab.Screen name="Scan" component={ScanScreen} />
        <Tab.Screen name="History" component={HistoryScreen} />
      </Tab.Navigator>
    </NavigationContainer>
  )
}
