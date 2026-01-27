interface StatusBadgeProps {
  status: string;
  type?: 'assessment' | 'approval' | 'severity';
}

function StatusBadge({ status, type = 'assessment' }: StatusBadgeProps) {
  const getClassName = () => {
    if (type === 'severity') {
      return `badge badge-${status}`;
    }

    const statusMap: Record<string, string> = {
      pass: 'badge-pass',
      fail: 'badge-fail',
      na: 'badge-na',
      exception: 'badge-exception',
      not_assessed: 'badge-not-assessed',
      pending: 'badge-pending',
      approved: 'badge-approved',
      rejected: 'badge-rejected',
      high: 'badge-high',
      medium: 'badge-medium',
      low: 'badge-low',
    };

    return `badge ${statusMap[status] || 'badge-na'}`;
  };

  const getLabel = () => {
    const labelMap: Record<string, string> = {
      pass: 'PASS',
      fail: 'FAIL',
      na: 'N/A',
      exception: 'EXCEPTION',
      not_assessed: 'Not Assessed',
      pending: 'Pending',
      approved: 'Approved',
      rejected: 'Rejected',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
    };

    return labelMap[status] || status;
  };

  return <span className={getClassName()}>{getLabel()}</span>;
}

export default StatusBadge;
