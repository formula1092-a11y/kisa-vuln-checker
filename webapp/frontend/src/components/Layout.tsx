import { Outlet, NavLink } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

function Layout() {
  const { user, logout } = useAuth();

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="sidebar-logo">KISA Vuln Checker</div>
        <nav>
          <ul className="sidebar-nav">
            <li>
              <NavLink to="/dashboard" className={({ isActive }) => isActive ? 'active' : ''}>
                Dashboard
              </NavLink>
            </li>
            <li>
              <NavLink to="/assets" className={({ isActive }) => isActive ? 'active' : ''}>
                Assets
              </NavLink>
            </li>
            <li>
              <NavLink to="/exceptions" className={({ isActive }) => isActive ? 'active' : ''}>
                Exceptions
              </NavLink>
            </li>
            <li>
              <NavLink to="/reports" className={({ isActive }) => isActive ? 'active' : ''}>
                Reports
              </NavLink>
            </li>
            <li>
              <NavLink to="/checklist" className={({ isActive }) => isActive ? 'active' : ''}>
                Checklist
              </NavLink>
            </li>
            <li>
              <NavLink to="/upload" className={({ isActive }) => isActive ? 'active' : ''}>
                Upload
              </NavLink>
            </li>
            {user?.role === 'admin' && (
              <li>
                <NavLink to="/users" className={({ isActive }) => isActive ? 'active' : ''}>
                  Users
                </NavLink>
              </li>
            )}
          </ul>
        </nav>
        <div className="user-menu">
          <div className="user-info">
            {user?.username} ({user?.role})
          </div>
          <button className="logout-btn" onClick={logout}>
            Logout
          </button>
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}

export default Layout;
