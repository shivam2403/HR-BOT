import './App.css';
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import Login from './pages/login/Login';
import Register from './pages/register/Register';
import { UserProvider } from './context/UserContext';
import Home from './pages/home/Home';
import HR from './pages/hr/Hr';

const router=createBrowserRouter([
  {
    path:'/',
    element:<Home/>
  },
  {
    path:'/login',
    element:<Login/>
  },
  {
    path:'/register',
    element:<Register/>
  },
  {
    path:'/hr',
    element:<HR/>
  },
])

function App() {
  return (
    <div className="App">
      <UserProvider>
        <RouterProvider router={router} />
      </UserProvider>
    </div>
  );
}

export default App;
