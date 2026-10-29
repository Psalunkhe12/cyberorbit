import { useAlerts } from '../hooks/useAlerts';

export default function DatabaseTest() {
  const { alerts, loading, error } = useAlerts();

  if (loading) {
    return <div>Loading alerts...</div>;
  }

  if (error) {
    return <div>{error}</div>;
  }

  return (
    <div>
      <h2>Database Alerts</h2>

      {alerts.map((alert) => (
        <div key={alert.id}>
          <strong>{alert.severity}</strong>
          {' - '}
          {alert.event}
        </div>
      ))}
    </div>
  );
}